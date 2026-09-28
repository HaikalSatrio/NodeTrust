"""Check that the local Neo4j from compose.yaml answers (NT-002).

    docker compose --profile neo4j up -d neo4j
    python scripts/check_neo4j.py              # reads NEO4J_PASSWORD from the environment or .env

Standard library only. It talks to loopback only, ignores proxy settings, and never prints the password.
Exit code 0 when Neo4j answers `RETURN 1`, 1 otherwise.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _password_from_dotenv(path: Path) -> str | None:
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key.strip() == "NEO4J_PASSWORD":
            return value.strip().strip('"').strip("'") or None
    return None


def check(url: str, password: str, timeout: float = 5.0) -> tuple[bool, str]:
    host = urlsplit(url).hostname
    if host not in LOOPBACK:
        return False, f"refusing non-loopback host {host!r}: this check is for the local compose service"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route loopback via a proxy
    base = url.rstrip("/")
    try:
        with opener.open(base + "/", timeout=timeout) as r:
            info = json.load(r)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, f"Neo4j not reachable at {base}: {e}"
    req = urllib.request.Request(
        base + "/db/neo4j/tx/commit", method="POST",
        data=json.dumps({"statements": [{"statement": "RETURN 1 AS ok"}]}).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "Authorization": "Basic " + base64.b64encode(f"neo4j:{password}".encode()).decode()})
    try:
        with opener.open(req, timeout=timeout) as r:
            body = json.load(r)
    except urllib.error.HTTPError as e:
        return False, f"query rejected with HTTP {e.code} (check NEO4J_PASSWORD)"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, f"query failed: {e}"
    if body.get("errors"):
        return False, "query error: " + str(body["errors"][0].get("message", ""))[:200]
    try:
        ok = body["results"][0]["data"][0]["row"] == [1]
    except (KeyError, IndexError, TypeError):
        ok = False
    if not ok:
        return False, "unexpected answer to RETURN 1"
    return True, f"Neo4j {info.get('neo4j_version', '?')} ({info.get('neo4j_edition', '?')}) answered RETURN 1"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default="http://127.0.0.1:7474")
    a = ap.parse_args(argv)
    password = os.environ.get("NEO4J_PASSWORD") or _password_from_dotenv(ROOT / ".env")
    if not password:
        print("NEO4J_PASSWORD is not set (environment or .env)", file=sys.stderr)
        return 1
    ok, message = check(a.url, password)
    print(("OK: " if ok else "FAIL: ") + message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
