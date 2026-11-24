"""Fail if any GitHub Action in .github/workflows is referenced by tag or branch instead of a full commit SHA (rule R7)."""

import re
import sys
from pathlib import Path

USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
DOCKER_PINNED = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def violations(text: str) -> list[str]:
    bad = []
    for ref in USES.findall(text):
        if ref.startswith("./"):
            continue  # local action in this repo
        if not (PINNED.match(ref) or DOCKER_PINNED.match(ref)):
            bad.append(ref)
    return bad


def main(root: Path) -> int:
    failed = False
    for wf in sorted((root / ".github" / "workflows").glob("*.y*ml")):
        for ref in violations(wf.read_text(encoding="utf-8")):
            print(f"{wf}: unpinned action {ref}")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]))
