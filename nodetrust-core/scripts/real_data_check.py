"""Offline check of normalisation, diff and scoring against REAL npm metadata (NT-007/009/010).

Real packuments are taken from the local npm cache (~/.npm/_cacache, or %LOCALAPPDATA%/npm-cache/_cacache on
Windows): full packuments that npm itself downloaded earlier (e.g. by `npm view`/`npm install`). Nothing is
fetched; every cached body is checked against its integrity hash before use.

    python scripts/real_data_check.py OUT_DIR [--cache PATH]

Writes OUT_DIR/packuments/*.json and OUT_DIR/real.db, runs `nodetrust ingest` on them and prints statistics.
The sample is whatever this machine happened to install: a convenience sample of mostly popular packages
with no ground truth. It measures robustness, speed and alert volume, NOT detection accuracy.
"""

from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "make-fetch-happen:request-cache:https://registry.npmjs.org/"


def default_cache() -> Path:
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "npm-cache" / "_cacache"
    return Path.home() / ".npm" / "_cacache"


def cached_packuments(cache: Path) -> dict[str, str]:
    """name -> integrity of the newest cached FULL packument (abbreviated 'corgi' documents are skipped)."""
    found: dict[str, tuple[float, str]] = {}
    for f in (cache / "index-v5").rglob("*"):
        if not f.is_file():
            continue
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                e = json.loads(line.split("\t", 1)[1])
            except (IndexError, ValueError):
                continue
            key = (e or {}).get("key", "")
            if not key.startswith(REGISTRY) or "/-/" in key or not e.get("integrity"):
                continue
            accept = ((e.get("metadata") or {}).get("reqHeaders") or {}).get("accept", "")
            if "vnd.npm.install-v1" in accept:
                continue
            name = urllib.parse.unquote(key[len(REGISTRY):])
            if e.get("time", 0) >= found.get(name, (-1, ""))[0]:
                found[name] = (e.get("time", 0), e["integrity"])
    return {n: integ for n, (_, integ) in found.items()}


def extract(cache: Path, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    stats = collections.Counter()
    for name, integrity in sorted(cached_packuments(cache).items()):
        algo, b64 = integrity.split()[0].split("-", 1)
        digest = base64.b64decode(b64).hex()
        f = cache / "content-v2" / algo / digest[:2] / digest[2:4] / digest[4:]
        if not f.is_file():
            stats["content_missing"] += 1
            continue
        data = f.read_bytes()
        if hashlib.new(algo, data).hexdigest() != digest:
            stats["integrity_mismatch"] += 1
            continue
        try:
            if json.loads(data).get("name") != name:
                raise ValueError
        except ValueError:
            stats["not_a_packument"] += 1
            continue
        (out / (name.replace("/", "__") + ".json")).write_bytes(data)
        stats["written"] += 1
    return dict(stats)


def report(db: Path, packuments: Path) -> None:
    import sqlite3

    sys.path.insert(0, str(ROOT / "src"))
    from nodetrust.registry.normalize import normalize_packument

    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT r.name, r.version, r.score, r.tier, r.reasons_json, v.published_at FROM risk_score r "
                       "JOIN pkg_version v USING (ecosystem, name, version)").fetchall()
    tiers = collections.Counter(r["tier"] for r in rows)
    print(f"scored versions: {len(rows)} in {len({r['name'] for r in rows})} packages")
    print("tiers:", {t: f"{tiers[t]} ({tiers[t] / max(len(rows), 1):.2%})"
                     for t in ("NORMAL", "WATCH", "INVESTIGATE", "CRITICAL")})
    fired, pkgs = collections.Counter(), collections.defaultdict(set)
    for r in rows:
        for x in json.loads(r["reasons_json"]):
            fired[x["rule"]] += 1
            pkgs[x["rule"]].add(r["name"])
    print("rules fired (versions / packages):")
    for rule, n in fired.most_common():
        print(f"  {rule:32s} {n:7d} / {len(pkgs[rule])}")
    print("INVESTIGATE and CRITICAL versions:")
    for r in sorted((r for r in rows if r["tier"] in ("INVESTIGATE", "CRITICAL")), key=lambda r: -r["score"]):
        rules = ", ".join(x["rule"] for x in json.loads(r["reasons_json"]))
        print(f"  {r['tier']:11s} {r['score']:3d} {r['name']}@{r['version']} ({(r['published_at'] or '')[:10]}): {rules}")
    rejects, with_rejects = collections.Counter(), 0
    for f in sorted(packuments.glob("*.json")):
        errors = normalize_packument(json.loads(f.read_text(encoding="utf-8"))).errors
        with_rejects += bool(errors)
        for e in errors:
            rejects[e.split(": ", 1)[-1][:40]] += 1
    print(f"normaliser item-level rejects: {sum(rejects.values())} in {with_rejects} packuments;",
          rejects.most_common(5))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out", type=Path)
    ap.add_argument("--cache", type=Path, default=default_cache())
    a = ap.parse_args()
    packuments, db = a.out / "packuments", a.out / "real.db"
    print("extract:", extract(a.cache, packuments))
    for suffix in ("", "-wal", "-shm"):
        Path(f"{db}{suffix}").unlink(missing_ok=True)
    env = {**os.environ, "NODETRUST_DB_PATH": str(db), "NODETRUST_LOG_LEVEL": "WARNING",
           "NODETRUST_ALLOW_NETWORK": "false", "PYTHONPATH": str(ROOT / "src")}
    t = time.perf_counter()
    proc = subprocess.run([sys.executable, "-m", "nodetrust.cli", "ingest", str(packuments)], env=env,
                          capture_output=True, text=True)
    print(f"ingest: exit {proc.returncode} in {time.perf_counter() - t:.0f}s:", proc.stdout.strip()[-300:])
    if proc.returncode:
        print(proc.stderr[-2000:], file=sys.stderr)
        return 1
    report(db, packuments)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
