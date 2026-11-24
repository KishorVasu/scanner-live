"""Local-agent boundary tests: traversal, absolute paths, symlink escapes, loops, secrets never opened.

Symlink tests need symlink rights. On Windows without Developer Mode or admin they are SKIPPED (reported, not passed);
Linux CI runs them.
"""

import json
import os
import pathlib

import pytest

from security_agent.paths import PathError, read_manifest, resolve_root, safe_join, walk
from security_agent.scan import scan_root


def _symlink(target, link, is_dir=False):
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"cannot create symlinks here ({type(e).__name__}); covered in Linux CI")


@pytest.fixture
def layout(tmp_path):
    root = tmp_path / "repo"
    (root / "web").mkdir(parents=True)
    (root / "web" / "package.json").write_text(json.dumps({"dependencies": {"next": "15.0.0"}}))
    (root / "web" / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"next": "15.0.0"}}, "node_modules/next": {"version": "15.0.0"}}}))
    (root / ".env").write_text("DB_PASSWORD=fixture-not-real")
    (root / "web" / "server.key").write_text("fixture")
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "node_modules" / "x" / "package.json").write_text("{}")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package.json").write_text(json.dumps({"dependencies": {"evil": "1.0.0"}}))
    (outside / "secret.txt").write_text("outside")
    return resolve_root(str(root)), outside


@pytest.mark.parametrize("rel", ["../outside/secret.txt", "web/../../outside/secret.txt", "..\\outside\\secret.txt"])
def test_parent_traversal_refused(layout, rel):
    root, _ = layout
    with pytest.raises(PathError):
        safe_join(root, rel)


@pytest.mark.parametrize("rel", ["/etc/passwd", "C:\\Windows\\win.ini", "C:/x", "", "a\0b"])
def test_absolute_and_odd_paths_refused(layout, rel):
    root, _ = layout
    with pytest.raises(PathError):
        safe_join(root, rel)


def test_secret_files_never_listed_or_read(layout):
    root, _ = layout
    tree = list(walk(root))
    assert ".env" not in tree and "web/server.key" not in tree
    assert not any(p.startswith("node_modules/") for p in tree)
    with pytest.raises(PathError):
        read_manifest(root, ".env")


def test_scan_never_opens_secret_files(layout, monkeypatch):
    root, _ = layout
    opened = []
    real_open = pathlib.Path.open

    def spy(self, *a, **kw):
        opened.append(self.name)
        return real_open(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "open", spy)
    payload, stats = scan_root("repo", str(root))
    assert ".env" not in opened and "server.key" not in opened
    assert stats["secret_files_skipped"] == 2
    assert {"package": "next", "version": "15.0.0"}.items() <= next(
        d for d in payload["dependencies"] if d["package"] == "next").items()
    assert "fixture-not-real" not in json.dumps(payload)


def test_symlink_file_escape_refused(layout):
    root, outside = layout
    _symlink(outside / "package.json", root / "package.json")
    assert "package.json" not in list(walk(root))
    with pytest.raises(PathError):
        safe_join(root, "package.json")
    payload, stats = scan_root("repo", str(root))
    assert stats["symlink_escapes_refused"] == 1
    assert all(d["package"] != "evil" for d in payload["dependencies"])


def test_symlink_dir_escape_not_followed(layout):
    root, outside = layout
    _symlink(outside, root / "linked", is_dir=True)
    assert not any(p.startswith("linked/") for p in walk(root))
    with pytest.raises(PathError):
        safe_join(root, "linked/package.json")


def test_symlink_loop_terminates(layout):
    root, _ = layout
    _symlink(root, root / "web" / "loop", is_dir=True)
    assert len(list(walk(root))) < 10


def test_server_roots_must_be_locally_allowed(layout, tmp_path):
    from security_agent.paths import locally_allowed

    root, outside = layout
    allow = [str(root)]
    assert locally_allowed(str(root), allow)
    assert locally_allowed(str(root / "web"), allow)
    assert not locally_allowed(str(outside), allow)
    assert not locally_allowed(str(root / ".." / "outside"), allow)  # traversal resolves outside
    assert not locally_allowed(str(root), [])


def test_root_must_exist(tmp_path):
    with pytest.raises(PathError):
        resolve_root(str(tmp_path / "missing"))
