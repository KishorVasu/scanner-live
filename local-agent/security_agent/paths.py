"""Filesystem boundary. Every path the agent touches is resolved and checked against an approved root.

Rules: no `..`, no absolute paths, no symlink (file or directory) that leaves the root, never descend into symlinked
directories (so no loops), never open secret-pattern files, never read outside `manifest_paths`.
"""

import hashlib
import os
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from sp_inventory import is_secret_path
from sp_inventory.detect import SKIP_DIRS

MAX_READ_BYTES = 20 * 1024 * 1024
MAX_HASH_BYTES = 200 * 1024 * 1024


class PathError(Exception):
    pass


def resolve_root(path: str) -> Path:
    real = Path(os.path.realpath(path))
    if not real.is_dir():
        raise PathError(f"approved root is not a directory: {path}")
    return real


def _inside(root: Path, real: Path) -> bool:
    return real == root or root in real.parents


def locally_allowed(path: str, local_allow: list[str]) -> bool:
    """True if `path` resolves inside one of the folders the machine owner allowed at registration."""
    try:
        real = Path(os.path.realpath(path))
    except (OSError, ValueError):
        return False
    return any(_inside(Path(a), real) for a in local_allow)


def safe_join(root: Path, rel: str) -> Path:
    """Resolve a repository-relative path inside `root`, or raise PathError."""
    norm = rel.replace("\\", "/")
    if not norm or norm.startswith("/") or (len(norm) > 1 and norm[1] == ":") or "\0" in norm:
        raise PathError(f"absolute or empty path refused: {rel!r}")
    parts = PurePosixPath(norm).parts
    if ".." in parts:
        raise PathError(f"parent traversal refused: {rel!r}")
    real = Path(os.path.realpath(root.joinpath(*parts)))
    if not _inside(root, real):
        raise PathError(f"path leaves the approved root: {rel!r}")
    # A link inside the root can still point at a secret file (requirements-dev.txt -> .env): check the target too.
    if real != root and is_secret_path(real.relative_to(root).as_posix()):
        raise PathError(f"path resolves to a secret-pattern file: {rel!r}")
    return real


def walk(root: Path, stats: dict | None = None) -> Iterator[str]:
    """Yield POSIX relative paths of regular files under root that are safe to consider."""
    stats = stats if stats is not None else {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        keep = []
        for d in dirnames:
            if d in SKIP_DIRS:
                continue
            if (base / d).is_symlink():
                stats["symlink_dirs_skipped"] = stats.get("symlink_dirs_skipped", 0) + 1
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in filenames:
            full = base / f
            rel = full.relative_to(root).as_posix()
            if is_secret_path(rel):
                stats["secret_files_skipped"] = stats.get("secret_files_skipped", 0) + 1
                continue
            if full.is_symlink():
                target = Path(os.path.realpath(full))
                if not _inside(root, target) or not target.is_file() or is_secret_path(
                        target.relative_to(root).as_posix()):
                    stats["symlink_escapes_refused"] = stats.get("symlink_escapes_refused", 0) + 1
                    continue
            elif not full.is_file():
                continue
            yield rel


def read_manifest(root: Path, rel: str) -> bytes | None:
    """Read one manifest/lockfile. Secret-pattern paths are refused before anything is opened."""
    if is_secret_path(rel):
        raise PathError(f"secret-pattern path refused: {rel!r}")
    real = safe_join(root, rel)
    if real.stat().st_size > MAX_READ_BYTES:
        return None
    return real.read_bytes()


def file_sha256(root: Path, rel: str) -> str | None:
    if is_secret_path(rel):
        return None
    real = safe_join(root, rel)
    if real.stat().st_size > MAX_HASH_BYTES:
        return None
    h = hashlib.sha256()
    with real.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
