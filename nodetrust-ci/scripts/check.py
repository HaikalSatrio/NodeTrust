"""Quality gate for nodetrust-ci (NT-040): compile, lint, test, secret scan, action hygiene.

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


def lint() -> bool | None:
    """pyflakes: unused imports, undefined names and similar. None when pyflakes is not installed."""
    import importlib.util
    import os

    if importlib.util.find_spec("pyflakes") is None:
        if os.environ.get("NODETRUST_REQUIRE_LINT") == "1":
            print("      pyflakes is required here (NODETRUST_REQUIRE_LINT=1) but not installed")
            return False
        return None
    dirs = [d for d in ("src", "tests", "e2e", "scripts") if (ROOT / d).is_dir()]
    return subprocess.call([sys.executable, "-m", "pyflakes", *dirs], cwd=ROOT) == 0


def report_lint(res: bool | None) -> bool:
    if res is None:
        print("      skipped: pyflakes is not installed (pip install pyflakes); CI always runs it")
    return res is not False


def workflows_pinned() -> list[str]:
    """Every `uses:` in .github/workflows must be pinned to a full commit SHA (tags are mutable)."""
    import re as _re

    bad = []
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        for i, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = _re.search(r"uses:\s*([^\s#]+)", line)
            if m and not m.group(1).startswith("./") and not _re.fullmatch(r"[0-9a-f]{40}", m.group(1).split("@")[-1]):
                bad.append(f"{wf.relative_to(ROOT)}:{i}: '{m.group(1)}' is not pinned to a full commit SHA")
    return bad


def main() -> int:
    ok = compileall.compile_dir(str(ROOT / "src"), quiet=1) and compileall.compile_dir(str(ROOT / "tests"), quiet=1)
    ok &= report_lint(lint())
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
    probs = action_hygiene() + workflows_pinned()
    for pr in probs:
        print("  " + pr)
    ok &= not hits and not probs
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
