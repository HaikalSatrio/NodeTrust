# Setup (NT-002)

## Local development

```bash
git clone https://github.com/HaikalSatrio/NodeTrust
cd NodeTrust/nodetrust-core
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env                  # optional NODETRUST_ADMIN_TOKEN (32+ chars); never commit .env
python scripts/check.py               # must print PASS
```

Because `nodetrust-ci` sits next to this folder, `check.py` also runs the local end-to-end suite
(`e2e/`: the real CI client against a running core over 127.0.0.1). Without it, that step is skipped.
The same venv also runs `nodetrust-ci`'s gate: `cd ../nodetrust-ci && python scripts/check.py`.

These steps were run on 27 Sep 2026 from fresh clones and empty venvs, installing from PyPI: Windows
(Python 3.12.4) and Linux (`python:3.11-slim` 3.11.16 and `python:3.12-slim` 3.12.14). Both gates printed
PASS, including lint and the e2e suite.

### Checking for secrets

`check.py` scans the working tree. To check every version of every file ever committed, including files
deleted later, run `python scripts/scan_history.py` (and `python scripts/scan_history.py ../nodetrust-ci`).
Token-shaped secrets or committed `.env`, database or key files fail it. Assignments that only look like a
secret are listed for a human to judge.

Python 3.11+ is required. Dependencies: FastAPI, uvicorn, pydantic (+settings), httpx, networkx.
Development adds pytest, pyflakes (lint) and cryptography (throwaway TLS certificates in the SMTP tests).
No secret is embedded in code or fixtures. The quality gate scans for them.

## Run

```bash
nodetrust create-project --name my-app --email owner@example.com   # prints the admin key once
nodetrust serve                                                      # 127.0.0.1:8080
nodetrust worker                                                     # feed/fetch (if network allowed) + alerts
```

Create a `ci` key for the repository with the admin key
(`POST /v1/projects/{pid}/keys {"role":"ci","label":"github"}`) and store it as a repository secret.

## Going online (server only)

Set `NODETRUST_ALLOW_NETWORK=true` and add packages to the watchlist (`POST /v1/watchlist`). The npm change
feed and packument fetch were checked live (`docs/audit/live-checks.md`); a first start begins at the feed's
current head, so history is not replayed unless you ask for it. For e-mail, set
`NODETRUST_SMTP_*`. Without SMTP, alerts go to the outbox directory as `.eml` files.

## Docker / Compose

`compose.yaml` and `Dockerfile` describe an API + worker on one volume:

```bash
cp .env.example .env         # set NODETRUST_ADMIN_TOKEN (32+ random characters) or leave it empty
docker compose up --build    # API on 127.0.0.1:8080, worker next to it
```

Verified on 26 Sep 2026 from a clean clone: images build, the API turns healthy, the worker runs, the demo
seeds inside the container and the API answers from the host. The root filesystem is read-only, the
process runs as a non-root user and every published port binds to 127.0.0.1. The full test suite and
pyflakes also pass inside the built image, with the newest dependency versions pip resolved there.
Base images are pinned by digest. If port 8080 is taken on your machine, set `NODETRUST_PORT` in `.env`.

## Neo4j (optional)

The MVP graph runs on SQLite + networkx (stand-in until NT-013), so Neo4j is not needed to run NodeTrust.
To work on the graph store, start the local Neo4j Community service:

```bash
echo "NEO4J_PASSWORD=<8+ characters>" >> .env      # never commit .env
docker compose --profile neo4j up -d neo4j         # Browser: http://127.0.0.1:7474, Bolt: 127.0.0.1:7687
python scripts/check_neo4j.py                      # prints OK when Neo4j answers RETURN 1
python scripts/spike_nt004.py                      # validates the manual dependency graph on real Neo4j
```

`check_neo4j.py` uses only the standard library, talks to loopback only and never prints the password.
Whether NodeTrust uses Neo4j and GDS, and under which licence, is decided in NT-013.
