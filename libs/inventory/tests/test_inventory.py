"""sp_inventory on synthetic fixtures (no real project data)."""

import json

from sp_inventory import build_inventory, is_secret_path, manifest_hash, manifest_paths, tree_hash
from sp_inventory import parsers


def j(obj) -> bytes:
    return json.dumps(obj).encode()


NPM_MANIFEST = j({"dependencies": {"next": "^15.0.0", "react": "19.0.0"}, "devDependencies": {"vitest": "^5"}})
NPM_LOCK = j({"lockfileVersion": 3, "packages": {
    "": {"name": "web"},
    "node_modules/next": {"version": "15.0.3"},
    "node_modules/react": {"version": "19.0.0"},
    "node_modules/next/node_modules/postcss": {"version": "8.4.31"},
}})


def test_npm_lock_resolves_versions_and_direct_flags():
    inv = build_inventory(["web/package.json", "web/package-lock.json"],
                          {"web/package.json": NPM_MANIFEST, "web/package-lock.json": NPM_LOCK})
    deps = {d["package"]: d for d in inv.dependencies}
    assert deps["next"]["version"] == "15.0.3" and deps["next"]["direct"]
    assert deps["postcss"]["version"] == "8.4.31" and not deps["postcss"]["direct"]
    prof = inv.profiles[0]
    assert (prof.framework, prof.framework_version, prof.package_manager) == ("nextjs", "15.0.3", "npm")
    assert inv.complete


def test_manifest_without_lockfile_is_incomplete():
    inv = build_inventory(["package.json"], {"package.json": NPM_MANIFEST})
    assert not inv.complete
    assert all(d["version"] is None and d["version_spec"] for d in inv.dependencies)


def test_unreadable_and_malformed_files_mark_incomplete():
    inv = build_inventory(["a/package.json", "a/package-lock.json"], {"a/package.json": NPM_MANIFEST, "a/package-lock.json": None})
    assert not inv.complete and {"path": "a/package-lock.json", "status": "not_read", "entries": 0} in inv.coverage
    inv = build_inventory(["composer.json"], {"composer.json": b"{not json"})
    assert not inv.complete and inv.coverage[0]["status"] == "parse_error"


def test_python_php_dart_ios_android_unity():
    tree = ["api/requirements.txt", "api/poetry.lock", "site/composer.json", "site/composer.lock",
            "app/pubspec.yaml", "app/pubspec.lock", "ios/Podfile.lock", "android/gradle.lockfile",
            "android/build.gradle", "game/ProjectSettings/ProjectVersion.txt", "game/Packages/manifest.json"]
    contents = {
        "api/requirements.txt": b"Django==5.1.2\nrequests>=2  # comment\n-r other.txt\n",
        "api/poetry.lock": b'[[package]]\nname = "Django"\nversion = "5.1.2"\n',
        "site/composer.json": j({"require": {"php": ">=8.2", "laravel/framework": "^11.0"}}),
        "site/composer.lock": j({"packages": [{"name": "laravel/framework", "version": "v11.9.0"}]}),
        "app/pubspec.yaml": b"dependencies:\n  flutter:\n    sdk: flutter\n",
        "app/pubspec.lock": b'packages:\n  http:\n    dependency: "direct main"\n    source: hosted\n    version: "1.2.2"\n'
                            b'sdks:\n  dart: ">=3.0.0"\n',
        "ios/Podfile.lock": b"PODS:\n  - Alamofire (5.9.1)\n  - Firebase/Core (10.0.0):\n    - X\n\nDEPENDENCIES:\n  - Alamofire\n",
        "android/gradle.lockfile": b"# lock\ncom.squareup.okhttp3:okhttp:4.12.0=releaseRuntimeClasspath\nempty=\n",
        "android/build.gradle": b"apply plugin: 'com.android.application'\n",
        "game/ProjectSettings/ProjectVersion.txt": b"m_EditorVersion: 2022.3.10f1\n",
        "game/Packages/manifest.json": j({"dependencies": {"com.unity.textmeshpro": "3.0.6"}}),
    }
    inv = build_inventory(tree, contents)
    got = {(d["ecosystem"], d["package"], d["version"]) for d in inv.dependencies}
    assert ("PyPI", "django", "5.1.2") in got
    assert ("Packagist", "laravel/framework", "11.9.0") in got
    assert ("Pub", "http", "1.2.2") in got
    assert ("CocoaPods", "Alamofire", "5.9.1") in got and ("CocoaPods", "Firebase", "10.0.0") in got
    assert ("Maven", "com.squareup.okhttp3:okhttp", "4.12.0") in got
    frameworks = {(p.ecosystem, p.framework) for p in inv.profiles}
    assert {("PyPI", "django"), ("Packagist", "laravel"), ("Pub", "flutter"), ("Maven", "android"),
            ("Unity", "unity")} <= frameworks


def test_yarn_and_pnpm_lines():
    yarn = b'"next@^15.0.0":\n  version "15.0.3"\n  resolved "x"\n\n"@scope/pkg@^1", "@scope/pkg@^1.1":\n  version "1.2.0"\n'
    assert {(d.package, d.version) for d in parsers.yarn_lock(yarn, {"next"})} == {("next", "15.0.3"), ("@scope/pkg", "1.2.0")}
    pnpm = b"lockfileVersion: '9.0'\npackages:\n  next@15.0.3:\n    resolution: {}\n  '@scope/pkg@1.2.0':\n    x: y\n"
    assert {(d.package, d.version) for d in parsers.pnpm_lock(pnpm, set())} == {("next", "15.0.3"), ("@scope/pkg", "1.2.0")}


def test_secret_paths_never_selected():
    tree = [".env", "config/.env.production", "certs/server.key", "id_rsa", "android/app/google-services.json",
            "package.json", ".npmrc", "node_modules/x/package.json"]
    assert all(is_secret_path(p) for p in tree[:5] + [".npmrc"])
    assert manifest_paths(tree) == ["package.json"]


def test_hashes_are_order_independent_and_change_with_content():
    a = manifest_hash({"x": b"1", "y": b"2"})
    assert a == manifest_hash({"y": b"2", "x": b"1"}) != manifest_hash({"x": b"1", "y": b"3"})
    assert tree_hash([("a", "1"), ("b", "2")]) == tree_hash([("b", "2"), ("a", "1")])
