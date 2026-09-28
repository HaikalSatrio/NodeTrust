"""Scan every file version in a repository's git history for secrets (NT-002 review: "validasi tidak ada secret").

    python scripts/scan_history.py                 # this repository
    python scripts/scan_history.py ../nodetrust-ci  # the CI repository

`check.py` only scans the working tree. This walks every blob reachable from any ref, so a secret that was
committed and later deleted is still found. It also lists files that should never be committed (.env,
databases, key files). Token-shaped matches fail the run (exit 1). Assignments that merely look like a
secret (`password = "..."`) are listed for a human to judge, because test values match them too.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

STRONG = [
    ("NodeTrust API key", re.compile(rb"ntk_[0-9a-f]{16}_[A-Za-z0-9_-]{40,}")),
    ("GitHub token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("npm token", re.compile(rb"npm_[A-Za-z0-9]{36}")),
    ("private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("AWS key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("Slack token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
]
REVIEW = [("assignment that looks like a secret",
           re.compile(rb"(?i)(?:password|passwd|secret|token|api_key)\s*[=:]\s*['\"][^'\"\s]{12,}['\"]"))]
NEVER_COMMIT = re.compile(r"(^|/)(\.env|[^/]*\.(db|db-wal|db-shm|sqlite|pem|key|p12|pfx)|id_[a-z0-9]+|outbox/.*|data/.*)$")


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True).stdout


def scan(repo: Path) -> int:
    objects = git(repo, "rev-list", "--all", "--objects").decode().splitlines()
    first_path: dict[str, str] = {}
    for line in objects:
        sha, _, path = line.partition(" ")
        if path:
            first_path.setdefault(sha, path)
    commits = len(git(repo, "rev-list", "--all").split())
    strong, review = [], []
    batch = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch"], input="\n".join(first_path).encode(),
                           capture_output=True, check=True).stdout
    pos = 0
    for sha in first_path:
        header_end = batch.index(b"\n", pos)
        _, kind, size = batch[pos:header_end].split()
        body = batch[header_end + 1: header_end + 1 + int(size)]
        pos = header_end + 1 + int(size) + 1
        if kind != b"blob":
            continue
        for label, pat in STRONG:
            strong += [(first_path[sha], label) for _ in pat.finditer(body)]
        for label, pat in REVIEW:
            review += [(first_path[sha], label, m.group(0)[:70].decode(errors="replace")) for m in pat.finditer(body)]
    bad_paths = sorted({p for p in first_path.values() if NEVER_COMMIT.search(p)})
    print(f"{repo.resolve().name}: {commits} commits, {len(first_path)} objects")
    print("  files that should never be committed:", ", ".join(bad_paths) or "none")
    print("  token-shaped secrets:", "none" if not strong else "")
    for path, label in strong:
        print(f"    FAIL {path}: {label}")
    if review:
        print("  for a human to judge (usually test values):")
        for path, label, text in review:
            print(f"    {path}: {text}")
    return 1 if strong or bad_paths else 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    raise SystemExit(scan(target))
