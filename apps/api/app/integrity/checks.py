"""Repository integrity checks (docs/SCANNING_STRATEGY.md §6). Pure, static functions over file bytes.

Nothing here executes, imports, renders or decodes-and-runs anything. Flagged content is described, never copied:
evidence holds paths, keys, sizes and hashes only.
"""

import fnmatch
import hashlib
import json
import posixpath
import re
from dataclasses import dataclass

from sp_inventory import is_secret_path

LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare")
BUILD_CONFIG = re.compile(r"(^|/)(vite|webpack|next|babel|rollup|esbuild)\.config\.[cm]?[jt]s$|(^|/)(\.babelrc|\.npmrc|\.yarnrc(\.yml)?)$")
WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
JS_FILE = re.compile(r"\.(m|c)?[jt]sx?$")
MAGIC = {
    ".png": [b"\x89PNG\r\n\x1a\n"], ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"], ".gif": [b"GIF87a", b"GIF89a"],
    ".ico": [b"\x00\x00\x01\x00"], ".woff": [b"wOFF"], ".woff2": [b"wOF2"], ".ttf": [b"\x00\x01\x00\x00", b"true"],
    ".otf": [b"OTTO"], ".webp": [b"RIFF"], ".pdf": [b"%PDF-"], ".zip": [b"PK\x03\x04"],
}
SCRIPT_MARKERS = (b"<script", b"eval(", b"#!/bin/", b"#!/usr/bin/", b"require(", b"child_process", b"powershell", b"Function(")
USES_REF = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{1000,}={0,2}")
HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")


@dataclass(frozen=True)
class Change:
    path: str
    before: bytes | None  # None: file added
    after: bytes | None  # None: file removed


@dataclass(frozen=True)
class Hit:
    kind: str  # repository_events.kind
    rule: str
    severity: str
    path: str
    detail: str
    line: int | None = None


def _sha(b: bytes | None) -> str:
    return hashlib.sha256(b or b"").hexdigest()[:16]


def _json(b: bytes | None) -> dict:
    if not b:
        return {}
    try:
        data = json.loads(b.decode("utf-8-sig"))
        return data if isinstance(data, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def _jsonc(b: bytes | None) -> dict:
    """VS Code files allow // and /* */ comments and trailing commas."""
    if not b:
        return {}
    s = b.decode("utf-8", errors="replace")
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r'(?m)^\s*//.*$|(?<=[,{\[\s])//[^"\n]*$', "", s)
    s = re.sub(r",\s*([}\]])", r"\1", s)
    try:
        data = json.loads(s)
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def check_lifecycle(c: Change) -> list[Hit]:
    hits = []
    base = posixpath.basename(c.path)
    if base == "package.json" and c.after is not None:
        before = (_json(c.before).get("scripts") or {}) if c.before else {}
        after = _json(c.after).get("scripts") or {}
        for name in LIFECYCLE_SCRIPTS:
            if name in after and name not in before:
                hits.append(Hit("lifecycle_script_change", f"npm-{name}-added", "high", c.path,
                                f"new `{name}` script ({len(str(after[name]))} chars, sha {_sha(str(after[name]).encode())})"))
            elif name in after and before.get(name) != after[name]:
                hits.append(Hit("lifecycle_script_change", f"npm-{name}-changed", "medium", c.path,
                                f"`{name}` script changed (sha {_sha(str(before.get(name)).encode())} -> {_sha(str(after[name]).encode())})"))
    if base == "setup.py" and c.after is not None and c.before != c.after:
        hits.append(Hit("lifecycle_script_change", "python-setup-py", "high" if c.before is None else "medium", c.path,
                        "setup.py added" if c.before is None else "setup.py changed (runs at install time)"))
    if base == "pyproject.toml" and c.after is not None:
        def backend(b):
            m = re.search(rb"(?ms)^\[build-system\].*?^build-backend\s*=\s*['\"]([^'\"]+)", b or b"")
            return m.group(1).decode() if m else None
        if backend(c.before) != backend(c.after):
            hits.append(Hit("lifecycle_script_change", "python-build-backend", "medium", c.path,
                            f"build backend changed: {backend(c.before)} -> {backend(c.after)}"))
    return hits


def check_editor(c: Change) -> list[Hit]:
    if c.after is None:
        return []
    if c.path.endswith(".vscode/tasks.json"):
        tasks = _jsonc(c.after).get("tasks") or []
        auto = [t.get("label", "?") for t in tasks if isinstance(t, dict)
                and (t.get("runOptions") or {}).get("runOn") == "folderOpen"]
        if auto:
            return [Hit("vscode_task", "vscode-folder-open-task", "high", c.path,
                        f"task(s) run automatically on folder open: {', '.join(map(str, auto))[:200]}")]
        if c.before != c.after:
            return [Hit("vscode_task", "vscode-tasks-changed", "medium", c.path, "tasks.json added or changed")]
    if c.path.endswith(".vscode/settings.json"):
        keys = lambda b: {k: v for k, v in _jsonc(b).items() if k.startswith(("terminal.integrated", "task."))}  # noqa: E731
        if keys(c.before) != keys(c.after):
            return [Hit("ide_config_change", "vscode-terminal-settings", "medium", c.path,
                        f"terminal/task settings changed: {sorted(set(keys(c.before)) | set(keys(c.after)))}"[:300])]
    if "/.idea/runConfigurations/" in "/" + c.path or c.path.endswith(".idea/workspace.xml"):
        if c.before != c.after:
            return [Hit("ide_config_change", "idea-run-config", "medium", c.path, "IDE run configuration added or changed")]
    return []


def check_build_config(c: Change) -> list[Hit]:
    if BUILD_CONFIG.search(c.path) and c.before != c.after and c.after is not None:
        verb = "added" if c.before is None else "changed"
        return [Hit("build_config_change", "build-config-changed", "medium", c.path,
                    f"build/package-manager config {verb} (sha {_sha(c.after)})")]
    return []


def check_workflow(c: Change) -> list[Hit]:
    if not WORKFLOW.match(c.path) or c.after is None or c.before == c.after:
        return []
    text = c.after.decode("utf-8", errors="replace")
    before = (c.before or b"").decode("utf-8", errors="replace")
    hits = []
    if "pull_request_target" in text and "pull_request_target" not in before:
        hits.append(Hit("workflow_change", "workflow-pull-request-target", "high", c.path,
                        "pull_request_target trigger added (runs with secrets on untrusted PRs)"))
    if re.search(r"permissions:\s*write-all", text) or (
            len(re.findall(r":\s*write\b", text)) > len(re.findall(r":\s*write\b", before))):
        hits.append(Hit("workflow_change", "workflow-permissions-broadened", "medium", c.path, "write permissions added"))
    unpinned = [r for r in USES_REF.findall(text) if not r.startswith("./") and not re.search(r"@[0-9a-f]{40}$", r)]
    if unpinned:
        hits.append(Hit("workflow_change", "workflow-unpinned-action", "medium", c.path,
                        f"actions referenced by tag/branch: {', '.join(sorted(set(unpinned)))[:300]}"))
    if not hits:
        hits.append(Hit("workflow_change", "workflow-changed", "low", c.path, "workflow added or changed"))
    return hits


def check_binary(c: Change) -> list[Hit]:
    ext = posixpath.splitext(c.path)[1].lower()
    if c.after is None or ext not in MAGIC:
        return []
    if not any(c.after.startswith(m) for m in MAGIC[ext]):
        return [Hit("suspicious_file", "binary-magic-mismatch", "high", c.path,
                    f"{ext} file does not start with a {ext} signature (sha {_sha(c.after)}, {len(c.after)} bytes)")]
    markers = [m.decode() for m in SCRIPT_MARKERS if m in c.after]
    if markers:
        return [Hit("suspicious_file", "binary-script-markers", "high", c.path,
                    f"{ext} file contains script markers {markers} (sha {_sha(c.after)})")]
    return []


def check_obfuscation(c: Change) -> list[Hit]:
    if c.after is None or not JS_FILE.search(c.path) or re.search(r"(^|/)(dist|build|vendor)/|\.min\.[cm]?js$", c.path):
        return []
    text = c.after.decode("utf-8", errors="replace")
    hits = []
    dyn = re.search(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(", text)
    decode = re.search(r"\batob\s*\(|Buffer\.from\([^)]*['\"]base64['\"]|String\.fromCharCode\s*\(", text)
    if dyn and decode:
        line = text.count("\n", 0, dyn.start()) + 1
        hits.append(Hit("suspicious_file", "js-eval-decoded", "high", c.path, "eval/Function used with decoded strings", line))
    if BASE64_BLOB.search(text):
        hits.append(Hit("suspicious_file", "js-large-base64", "medium", c.path, "base64 blob of 1000+ characters"))
    if len(HEX_ESCAPE.findall(text)) >= 200:
        hits.append(Hit("suspicious_file", "js-hex-escapes", "medium", c.path, "200+ hex-escaped characters"))
    longest = max((len(l) for l in text.splitlines()), default=0)
    if longest > 5000 and not hits:
        hits.append(Hit("suspicious_file", "js-very-long-line", "low", c.path, f"single line of {longest} characters"))
    return hits


def check_ignored_committed(tree: list[str], gitignore: bytes | None) -> list[Hit]:
    """Files present in the tree that the root .gitignore says should be ignored (simplified gitignore semantics)."""
    patterns = []
    for raw in (gitignore or b"").decode("utf-8", errors="replace").splitlines():
        p = raw.strip()
        if p and not p.startswith(("#", "!")):
            patterns.append(p)
    hits = []
    for path in tree:
        for p in patterns:
            anchored, directory = p.startswith("/"), p.endswith("/")
            pat = p.strip("/")
            parts = path.split("/")
            if directory:
                match = any(fnmatch.fnmatch(seg, pat) for seg in parts[:-1]) if not anchored else fnmatch.fnmatch(parts[0], pat)
            elif "/" in pat or anchored:
                match = fnmatch.fnmatch(path, pat)
            else:
                match = fnmatch.fnmatch(parts[-1], pat)
            if match:
                sev = "high" if is_secret_path(path) else "low"
                hits.append(Hit("ignored_file_committed", "gitignored-file-in-tree", sev, path, f"matches .gitignore `{p}`"))
                break
    return hits


CHANGE_CHECKS = (check_lifecycle, check_editor, check_build_config, check_workflow, check_binary, check_obfuscation)


def run_checks(changes: list[Change], tree: list[str] | None = None, gitignore: bytes | None = None) -> list[Hit]:
    hits = [h for c in changes for check in CHANGE_CHECKS for h in check(c)]
    if tree is not None:
        hits += check_ignored_committed(tree, gitignore)
    return hits
