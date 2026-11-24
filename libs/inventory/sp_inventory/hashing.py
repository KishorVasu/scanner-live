import hashlib
from collections.abc import Iterable, Mapping


def _digest(lines: Iterable[str]) -> str:
    h = hashlib.sha256()
    for line in lines:
        h.update(line.encode())
    return h.hexdigest()


def manifest_hash(files: Mapping[str, bytes]) -> str:
    """Hash of manifests and lockfiles: changes when any of them changes, independent of order."""
    return _digest(f"{p}\0{hashlib.sha256(c).hexdigest()}\n" for p, c in sorted(files.items()))


def tree_hash(entries: Iterable[tuple[str, str]]) -> str:
    """Hash of (path, content sha256) pairs for source files."""
    return _digest(f"{p}\0{h}\n" for p, h in sorted(entries))
