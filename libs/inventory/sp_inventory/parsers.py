"""Manifest and lockfile parsers. Input is untrusted bytes; parsers never execute anything.

Each parser returns a list of Dep. A parser raises ValueError on malformed input; the caller records it in coverage.
"""

import json
import re
import tomllib
from dataclasses import dataclass


@dataclass(frozen=True)
class Dep:
    ecosystem: str
    package: str
    version: str | None  # resolved version (lockfiles)
    version_spec: str | None  # declared range (manifests)
    direct: bool


def _json(content: bytes) -> dict:
    data = json.loads(content.decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


def _toml(content: bytes) -> dict:
    return tomllib.loads(content.decode("utf-8-sig"))


# ---- npm ----

def npm_manifest_deps(content: bytes) -> dict[str, str]:
    data = _json(content)
    out: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section = data.get(key) or {}
        if isinstance(section, dict):
            out.update({str(k): str(v) for k, v in section.items()})
    return out


def package_json(content: bytes) -> list[Dep]:
    return [Dep("npm", n, None, s, True) for n, s in npm_manifest_deps(content).items()]


def package_lock(content: bytes, direct: set[str]) -> list[Dep]:
    data = _json(content)
    deps: dict[tuple[str, str], Dep] = {}
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict) or "version" not in meta:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            top = path.count("node_modules/") == 1
            deps[(name, str(meta["version"]))] = Dep("npm", name, str(meta["version"]), None, top and name in direct)
    else:  # lockfile v1
        def walk(tree: dict, top: bool) -> None:
            for name, meta in (tree or {}).items():
                if isinstance(meta, dict) and "version" in meta:
                    deps[(name, str(meta["version"]))] = Dep("npm", name, str(meta["version"]), None, top and name in direct)
                    walk(meta.get("dependencies") or {}, False)

        walk(data.get("dependencies") or {}, True)
    return list(deps.values())


_YARN_HEADER = re.compile(r'^"?((?:@[^@/"\s]+/)?[^@"\s]+)@')
_LOCK_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def yarn_lock(content: bytes, direct: set[str]) -> list[Dep]:
    deps: dict[tuple[str, str], Dep] = {}
    current: str | None = None
    for line in content.decode("utf-8", errors="replace").splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
            m = _YARN_HEADER.match(line.strip())
            current = m.group(1) if m else None
        elif current and (m := _LOCK_VERSION.match(line)):
            deps[(current, m.group(1))] = Dep("npm", current, m.group(1), None, current in direct)
            current = None
    return list(deps.values())


_PNPM_KEY = re.compile(r"^  '?/?((?:@[^@/'\s]+/)?[^@'\s(]+)@([^('\s:]+)")


def pnpm_lock(content: bytes, direct: set[str]) -> list[Dep]:
    deps: dict[tuple[str, str], Dep] = {}
    section = None
    for line in content.decode("utf-8", errors="replace").splitlines():
        if line and not line[0].isspace():
            section = line.rstrip(":").strip()
            continue
        if section in ("packages", "snapshots") and (m := _PNPM_KEY.match(line)):
            name, version = m.group(1), m.group(2)
            deps[(name, version)] = Dep("npm", name, version, None, name in direct)
    return list(deps.values())


# ---- Python ----

_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirements_txt(content: bytes) -> list[Dep]:
    out = []
    for raw in content.decode("utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http:", "https:", "file:")):
            continue  # options, includes and URL requirements are not resolved here
        m = _REQ.match(line.split(";", 1)[0])
        if not m:
            continue
        spec = m.group(3).strip()
        pinned = spec[2:].strip() if spec.startswith("==") and "*" not in spec and "," not in spec else None
        out.append(Dep("PyPI", _norm_py(m.group(1)), pinned, spec or None, True))
    return out


def pyproject_toml(content: bytes) -> list[Dep]:
    data = _toml(content)
    out = []
    for req in (data.get("project") or {}).get("dependencies") or []:
        m = _REQ.match(str(req).split(";", 1)[0])
        if m:
            out.append(Dep("PyPI", _norm_py(m.group(1)), None, m.group(3).strip() or None, True))
    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name, spec in poetry.items():
        if name.lower() != "python":
            out.append(Dep("PyPI", _norm_py(name), None, spec if isinstance(spec, str) else None, True))
    return out


def toml_lock(content: bytes, direct: set[str]) -> list[Dep]:
    """poetry.lock and uv.lock both use [[package]] name/version."""
    data = _toml(content)
    return [
        Dep("PyPI", _norm_py(str(p["name"])), str(p["version"]), None, _norm_py(str(p["name"])) in direct)
        for p in data.get("package") or []
        if isinstance(p, dict) and "name" in p and "version" in p
    ]


def pipfile_lock(content: bytes) -> list[Dep]:
    data = _json(content)
    out = []
    for section, direct in (("default", True), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            ver = str(meta.get("version", "")).lstrip("=") or None if isinstance(meta, dict) else None
            out.append(Dep("PyPI", _norm_py(name), ver, None, direct))
    return out


# ---- PHP ----

def composer_json(content: bytes) -> list[Dep]:
    data = _json(content)
    out = []
    for key in ("require", "require-dev"):
        for name, spec in (data.get(key) or {}).items():
            if "/" in name:  # skip php and ext-* platform requirements
                out.append(Dep("Packagist", name.lower(), None, str(spec), True))
    return out


def composer_lock(content: bytes, direct: set[str]) -> list[Dep]:
    data = _json(content)
    return [
        Dep("Packagist", str(p["name"]).lower(), str(p["version"]).lstrip("v"), None, str(p["name"]).lower() in direct)
        for key in ("packages", "packages-dev")
        for p in data.get(key) or []
        if isinstance(p, dict) and "name" in p and "version" in p
    ]


# ---- Dart / Flutter ----

def pubspec_lock(content: bytes) -> list[Dep]:
    """Line parser for pubspec.lock (YAML subset): packages -> name -> dependency/version."""
    out, name, info, in_packages = [], None, {}, False

    def flush() -> None:
        if name and "version" in info:
            out.append(Dep("Pub", name, info["version"], None, info.get("dependency", "").startswith("direct")))

    for line in content.decode("utf-8", errors="replace").splitlines():
        if not line.startswith(" "):
            flush()
            name, info = None, {}
            in_packages = line.strip() == "packages:"
            continue
        if not in_packages:
            continue
        if re.match(r"^  [^\s].*:\s*$", line):
            flush()
            name, info = line.strip().rstrip(":").strip('"'), {}
        elif m := re.match(r'^    (dependency|version):\s*"?([^"]+)"?\s*$', line):
            info[m.group(1)] = m.group(2)
    flush()
    return out


# ---- iOS ----

_POD = re.compile(r"^  - \"?([^\s\"(]+) \(([^)]+)\)")


def podfile_lock(content: bytes) -> list[Dep]:
    out, in_pods = [], False
    for line in content.decode("utf-8", errors="replace").splitlines():
        if not line.startswith(" "):
            in_pods = line.strip() == "PODS:"
        elif in_pods and (m := _POD.match(line)):
            out.append(Dep("CocoaPods", m.group(1).split("/")[0], m.group(2), None, True))
    return list({(d.package, d.version): d for d in out}.values())


def package_resolved(content: bytes) -> list[Dep]:
    data = _json(content)
    pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
    out = []
    for p in pins:
        loc = p.get("location") or p.get("repositoryURL")
        ver = (p.get("state") or {}).get("version")
        if loc:
            out.append(Dep("SwiftURL", str(loc), ver, None, True))
    return out


# ---- Android / JVM ----

def gradle_lockfile(content: bytes) -> list[Dep]:
    out = []
    for line in content.decode("utf-8", errors="replace").splitlines():
        coord = line.split("=", 1)[0].strip()
        parts = coord.split(":")
        if len(parts) == 3 and not line.startswith("#"):
            out.append(Dep("Maven", f"{parts[0]}:{parts[1]}", parts[2], None, True))
    return out


# ---- Unity ----

def unity_manifest(content: bytes) -> list[Dep]:
    data = _json(content)
    return [Dep("Unity", n, v if not str(v).startswith(("file:", "http", "git")) else None, str(v), True)
            for n, v in (data.get("dependencies") or {}).items()]


def unity_lock(content: bytes) -> list[Dep]:
    data = _json(content)
    return [Dep("Unity", n, str(m.get("version")), None, m.get("depth") == 0)
            for n, m in (data.get("dependencies") or {}).items() if isinstance(m, dict)]
