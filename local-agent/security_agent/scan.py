"""Build the inventory payload for one approved root. Only structured results leave the machine, never file contents."""

from pathlib import Path

from sp_inventory import build_inventory, manifest_paths, tree_hash

from security_agent.paths import PathError, file_sha256, read_manifest, resolve_root, walk


def scan_root(alias: str, path: str) -> tuple[dict, dict]:
    """Return (payload for /api/agents/me/inventory, local stats for the operation log)."""
    root: Path = resolve_root(path)
    stats: dict = {}
    tree = list(walk(root, stats))
    contents: dict[str, bytes | None] = {}
    for rel in manifest_paths(tree):
        try:
            contents[rel] = read_manifest(root, rel)
        except (PathError, OSError):
            contents[rel] = None
    hashes = []
    for rel in tree:
        try:
            digest = file_sha256(root, rel)
        except (PathError, OSError):
            digest = None
        if digest:
            hashes.append((rel, digest))
    inv = build_inventory(tree, contents).as_dict()
    stats.update({"files": len(tree), "manifests": len(contents)})
    payload = {
        "alias": alias,
        "manifest_hash": inv["manifest_hash"],
        "tree_hash": tree_hash(hashes),
        "complete": inv["complete"],
        "profiles": inv["profiles"],
        "dependencies": inv["dependencies"],
        "coverage": inv["coverage"],
    }
    return payload, stats
