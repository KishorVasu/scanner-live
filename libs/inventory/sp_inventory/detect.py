"""Technology detection and inventory assembly from a file tree plus manifest contents.

Callers (GitHub discovery on the server, the local agent on a developer machine) supply:
  1. the list of file paths in the repository (POSIX, relative), and
  2. the bytes of the paths returned by `manifest_paths` (or None if a file could not be read).
"""

import posixpath
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field

from sp_inventory import parsers
from sp_inventory.hashing import manifest_hash
from sp_inventory.parsers import Dep

MAX_MANIFEST_BYTES = 20 * 1024 * 1024

# Never read, upload or hash these (rule: the agent never sends .env*, key files or secret-pattern files).
_SECRET = re.compile(
    r"(^|/)(\.env(\..*)?|.*\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx|asc|gpg)|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|"
    r"\.netrc|\.pgpass|\.npmrc|\.pypirc|credentials(\..*)?|secrets?\.(json|ya?ml|toml)|"
    r"google-services\.json|GoogleService-Info\.plist|service[-_]?account.*\.json)$",
    re.IGNORECASE,
)

# Large or generated trees that never hold the project's own manifests.
SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", ".dart_tool", "build", "dist", ".next",
    "Pods", "DerivedData", ".gradle", "Library", "Temp", "obj", ".idea", ".vs", "coverage", ".terraform",
})

# basename -> (ecosystem, kind, package manager)
_BASENAMES: dict[str, tuple[str, str, str]] = {
    "package.json": ("npm", "manifest", "npm"),
    "package-lock.json": ("npm", "lockfile", "npm"),
    "npm-shrinkwrap.json": ("npm", "lockfile", "npm"),
    "yarn.lock": ("npm", "lockfile", "yarn"),
    "pnpm-lock.yaml": ("npm", "lockfile", "pnpm"),
    "pyproject.toml": ("PyPI", "manifest", "pip"),
    "Pipfile": ("PyPI", "manifest", "pipenv"),
    "poetry.lock": ("PyPI", "lockfile", "poetry"),
    "uv.lock": ("PyPI", "lockfile", "uv"),
    "Pipfile.lock": ("PyPI", "lockfile", "pipenv"),
    "composer.json": ("Packagist", "manifest", "composer"),
    "composer.lock": ("Packagist", "lockfile", "composer"),
    "pubspec.yaml": ("Pub", "manifest", "pub"),
    "pubspec.lock": ("Pub", "lockfile", "pub"),
    "Podfile": ("CocoaPods", "manifest", "cocoapods"),
    "Podfile.lock": ("CocoaPods", "lockfile", "cocoapods"),
    "Package.swift": ("SwiftURL", "manifest", "swiftpm"),
    "Package.resolved": ("SwiftURL", "lockfile", "swiftpm"),
    "build.gradle": ("Maven", "manifest", "gradle"),
    "build.gradle.kts": ("Maven", "manifest", "gradle"),
    "gradle.lockfile": ("Maven", "lockfile", "gradle"),
    "Dockerfile": ("Docker", "manifest", "docker"),
}
_UNITY = {
    "Packages/manifest.json": "manifest",
    "Packages/packages-lock.json": "lockfile",
    "ProjectSettings/ProjectVersion.txt": "manifest",
}
_REQUIREMENTS = re.compile(r"(^|/)requirements[^/]*\.txt$")
_WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")

# Framework markers: ecosystem -> [(package, framework)], first match wins.
_FRAMEWORKS = {
    "npm": [("next", "nextjs"), ("react-native", "react-native"), ("@nestjs/core", "nestjs"), ("nuxt", "nuxt"),
            ("@angular/core", "angular"), ("vue", "vue"), ("react", "react"), ("express", "express"),
            ("fastify", "fastify"), ("koa", "koa")],
    "PyPI": [("django", "django"), ("fastapi", "fastapi"), ("flask", "flask")],
    "Packagist": [("laravel/framework", "laravel"), ("symfony/framework-bundle", "symfony")],
}


@dataclass
class Profile:
    ecosystem: str
    directory: str
    package_manager: str
    manifest_path: str | None = None
    lockfile_path: str | None = None
    framework: str | None = None
    framework_version: str | None = None


@dataclass
class Inventory:
    profiles: list[Profile] = field(default_factory=list)
    dependencies: list[dict] = field(default_factory=list)
    coverage: list[dict] = field(default_factory=list)  # per manifest: path, status, entries
    complete: bool = True  # False if any manifest could not be parsed or versions are unresolved
    manifest_hash: str = ""

    def as_dict(self) -> dict:
        return {
            "profiles": [asdict(p) for p in self.profiles],
            "dependencies": self.dependencies,
            "coverage": self.coverage,
            "complete": self.complete,
            "manifest_hash": self.manifest_hash,
        }


def is_secret_path(path: str) -> bool:
    return bool(_SECRET.search(path.replace("\\", "/")))


def _skipped(path: str) -> bool:
    return any(part in SKIP_DIRS for part in path.split("/")[:-1])


def _classify(path: str) -> tuple[str, str, str] | None:
    for suffix, kind in _UNITY.items():
        if path == suffix or path.endswith("/" + suffix):
            return ("Unity", kind, "upm")
    base = posixpath.basename(path)
    if base in _BASENAMES:
        return _BASENAMES[base]
    if _REQUIREMENTS.search(path):
        return ("PyPI", "manifest", "pip")
    return None


def manifest_paths(tree: list[str]) -> list[str]:
    """Paths whose contents the caller should read. Never includes secret-pattern files."""
    return sorted(p for p in tree if not _skipped(p) and not is_secret_path(p) and _classify(p))


def _directory(path: str) -> str:
    for suffix in _UNITY:
        if path == suffix or path.endswith("/" + suffix):
            return path[: -len(suffix)].rstrip("/") or "."
    return posixpath.dirname(path) or "."


def _parse(path: str, eco: str, kind: str, content: bytes, direct: set[str]) -> list[Dep]:
    base = posixpath.basename(path)
    if eco == "npm":
        if base == "package.json":
            return parsers.package_json(content)
        if base == "yarn.lock":
            return parsers.yarn_lock(content, direct)
        if base == "pnpm-lock.yaml":
            return parsers.pnpm_lock(content, direct)
        return parsers.package_lock(content, direct)
    if eco == "PyPI":
        if base == "pyproject.toml":
            return parsers.pyproject_toml(content)
        if base in ("poetry.lock", "uv.lock"):
            return parsers.toml_lock(content, direct)
        if base == "Pipfile.lock":
            return parsers.pipfile_lock(content)
        if base == "Pipfile":
            raise NotImplementedError
        return parsers.requirements_txt(content)
    if eco == "Packagist":
        return parsers.composer_json(content) if kind == "manifest" else parsers.composer_lock(content, direct)
    if eco == "Pub":
        if kind == "manifest":
            return []  # pubspec.yaml: detection only; versions come from pubspec.lock
        return parsers.pubspec_lock(content)
    if eco == "CocoaPods":
        if kind == "manifest":
            return []
        return parsers.podfile_lock(content)
    if eco == "SwiftURL":
        if kind == "manifest":
            return []
        return parsers.package_resolved(content)
    if eco == "Maven":
        if kind == "manifest":
            return []
        return parsers.gradle_lockfile(content)
    if eco == "Unity":
        if base == "manifest.json":
            return parsers.unity_manifest(content)
        if base == "packages-lock.json":
            return parsers.unity_lock(content)
        return []
    return []  # Docker: detection only


def build_inventory(tree: list[str], contents: Mapping[str, bytes | None]) -> Inventory:
    inv = Inventory()
    paths = manifest_paths(tree)
    groups: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for p in paths:
        eco, kind, pm = _classify(p)
        groups.setdefault((_directory(p), eco), []).append((p, kind, pm))

    read_files: dict[str, bytes] = {}
    for (directory, eco), files in sorted(groups.items()):
        files.sort(key=lambda f: f[1] != "manifest")  # manifests first: they decide which deps are direct
        profile = Profile(ecosystem=eco, directory=directory, package_manager=files[0][2])
        direct: set[str] = set()
        manifest_deps: list[Dep] = []
        lock_deps: list[Dep] | None = None
        for path, kind, pm in files:
            content = contents.get(path)
            if kind == "manifest":
                profile.manifest_path = profile.manifest_path or path
            else:
                profile.lockfile_path, profile.package_manager = path, pm
            if content is None:
                inv.coverage.append({"path": path, "status": "not_read", "entries": 0})
                inv.complete = False
                continue
            if len(content) > MAX_MANIFEST_BYTES:
                inv.coverage.append({"path": path, "status": "too_large", "entries": 0})
                inv.complete = False
                continue
            read_files[path] = content
            try:
                deps = _parse(path, eco, kind, content, direct)
            except NotImplementedError:
                inv.coverage.append({"path": path, "status": "unsupported", "entries": 0})
                continue
            except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
                inv.coverage.append({"path": path, "status": "parse_error", "entries": 0})
                inv.complete = False
                continue
            inv.coverage.append({"path": path, "status": "parsed", "entries": len(deps)})
            if kind == "manifest":
                manifest_deps += deps
                direct |= {d.package for d in deps}
            else:
                lock_deps = (lock_deps or []) + deps
            if eco == "Unity" and path.endswith("ProjectVersion.txt"):
                m = re.search(r"m_EditorVersion:\s*(\S+)", content.decode("utf-8", errors="replace"))
                profile.framework, profile.framework_version = "unity", m.group(1) if m else None
            if eco == "Pub" and kind == "manifest" and b"sdk: flutter" in content:
                profile.framework = "flutter"
            if eco == "Maven" and kind == "manifest" and b"com.android." in content:
                profile.framework = "android"

        chosen = lock_deps if lock_deps is not None else manifest_deps
        if lock_deps is None and manifest_deps and eco not in ("Docker",):
            # Declared ranges only: versions are unresolved, so absence of a match proves nothing.
            inv.complete = False
        for d in chosen:
            inv.dependencies.append({"ecosystem": d.ecosystem, "package": d.package, "version": d.version,
                                     "version_spec": d.version_spec, "direct": d.direct or d.package in direct,
                                     "manifest_path": profile.lockfile_path or profile.manifest_path})
        for pkg, fw in _FRAMEWORKS.get(eco, []):
            hit = next((d for d in chosen if d.package == pkg), None)
            if hit:
                profile.framework, profile.framework_version = fw, hit.version or hit.version_spec
                break
        inv.profiles.append(profile)

    if any(p.endswith(".xcodeproj/project.pbxproj") for p in tree) and not any(
        p.ecosystem in ("CocoaPods", "SwiftURL") for p in inv.profiles
    ):
        inv.profiles.append(Profile(ecosystem="Apple", directory=".", package_manager="xcode", framework="ios"))
    if any(_WORKFLOW.match(p) for p in tree):
        inv.profiles.append(Profile(ecosystem="GitHubActions", directory=".github/workflows", package_manager="github-actions"))

    inv.manifest_hash = manifest_hash(read_files)
    return inv
