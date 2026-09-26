"""Quality gate (NT-040): run before every merge, locally and in CI.

    python scripts/check.py

1. byte-compile every Python file (syntax errors) and lint it with pyflakes,
2. run the test suite (tests block all non-loopback network access), plus the local e2e suite
   when nodetrust-ci is cloned next to this repository,
3. scan tracked-looking files for committed secrets,
4. check the dashboard has no external resources (CSP 'self' only).
Exit code is non-zero if any step fails.
"""

from __future__ import annotations

import compileall
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", "data", "dist", "build"}
SECRET_PATTERNS = [
    ("NodeTrust API key", re.compile(r"ntk_[0-9a-f]{16}_[A-Za-z0-9_-]{40,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("npm token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("AWS key", re.compile(r"AKIA[0-9A-Z]{16}")),
]
TEXT_EXT = {".py", ".js", ".html", ".css", ".json", ".md", ".yml", ".yaml", ".toml", ".txt", ".cfg", ".ini", ".env",
            ".example", ""}


def files():
    for p in ROOT.rglob("*"):
        if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP_DIRS) and p.suffix in TEXT_EXT:
            yield p


def secret_scan() -> list[str]:
    hits = []
    for p in files():
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                hits.append(f"{p.relative_to(ROOT)}:{line}: possible {label}")
    return hits


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


def dashboard_is_self_contained() -> list[str]:
    bad = []
    for p in (ROOT / "src" / "nodetrust" / "dashboard" / "static").glob("*"):
        text = p.read_text(encoding="utf-8")
        for m in re.finditer(r"(?:src|href)\s*=\s*[\"'](https?:)?//", text):
            bad.append(f"{p.name}: external resource reference")
        if p.suffix == ".js" and re.search(r"fetch\(\s*[\"']https?://", text):
            bad.append(f"{p.name}: fetch to an absolute external URL")
        if p.suffix == ".html" and ("<script>" in text or " style=" in text):
            bad.append(f"{p.name}: inline script/style (blocked by CSP)")
    return bad


def main() -> int:
    ok = True
    print("[1/4] compileall + lint (pyflakes)")
    ok &= all(compileall.compile_dir(str(ROOT / d), quiet=1) for d in ("src", "tests", "e2e"))
    ok &= report_lint(lint())
    print("[2/4] tests")
    ok &= subprocess.call([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=ROOT) == 0
    if (ROOT.parent / "nodetrust-ci" / "src" / "nodetrust_ci" / "cli.py").is_file():
        print("      e2e (nodetrust-ci found next to this repo)")
        # -p no:asyncio makes pyproject's asyncio option unknown here; that warning is noise, not a problem.
        ok &= subprocess.call([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:asyncio",
                               "-W", "ignore::pytest.PytestConfigWarning", "e2e"], cwd=ROOT) == 0
    else:
        print("      e2e skipped: clone nodetrust-ci next to this repo to run it")
    print("[3/4] secret scan")
    hits = secret_scan()
    for h in hits:
        print("  " + h)
    ok &= not hits
    print("[4/4] dashboard self-contained, workflow actions pinned")
    bad = dashboard_is_self_contained() + workflows_pinned()
    for b in bad:
        print("  " + b)
    ok &= not bad
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
