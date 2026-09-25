"""Quality gate for nodetrust-ci (NT-040): compile, test, secret scan, action hygiene.

    python scripts/check.py
"""

from __future__ import annotations

import compileall
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
SECRET = re.compile(r"ntk_[0-9a-f]{16}_[A-Za-z0-9_-]{40,}|gh[pousr]_[A-Za-z0-9]{36,}|npm_[A-Za-z0-9]{36}|"
                    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


def action_hygiene() -> list[str]:
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    problems = []
    # inputs must never be interpolated inside `run:` blocks (script injection)
    in_run = False
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("run:"):
            in_run = True
            continue
        if in_run and re.match(r"^\s*(- name:|env:|shell:|if:|id:|working-directory:)", line):
            in_run = False
        if in_run and "${{" in line:
            problems.append(f"action.yml:{i}: expression inside run block (pass it via env instead)")
    for m in re.finditer(r"uses:\s*([^\s]+)", text):
        ref = m.group(1).split("@")[-1]
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            problems.append(f"action.yml: '{m.group(1)}' is not pinned to a full commit SHA")
    return problems


def main() -> int:
    ok = compileall.compile_dir(str(ROOT / "src"), quiet=1) and compileall.compile_dir(str(ROOT / "tests"), quiet=1)
    ok &= subprocess.call([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:asyncio"],
                          cwd=ROOT) == 0
    hits = []
    for p in ROOT.rglob("*"):
        if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP):
            try:
                t = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            hits += [f"{p.relative_to(ROOT)}: possible secret" for _ in SECRET.finditer(t)]
    for h in hits:
        print("  " + h)
    probs = action_hygiene()
    for pr in probs:
        print("  " + pr)
    ok &= not hits and not probs
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
