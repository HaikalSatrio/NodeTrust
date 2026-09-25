# Setup (NT-002)

## Local development

```bash
git clone <nodetrust-core>            # and nodetrust-ci next to it
cd nodetrust-core
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env                  # set NODETRUST_ADMIN_TOKEN; never commit .env
python scripts/check.py               # must print PASS
```

Python 3.11+ is required. Dependencies: FastAPI, uvicorn, pydantic (+settings), httpx, networkx, pytest.
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

Set `NODETRUST_ALLOW_NETWORK=true` and add packages to the watchlist (`POST /v1/watchlist`). Before relying
on the feed, verify the npm change-feed endpoint and response format (open item in NT-006). For e-mail, set
`NODETRUST_SMTP_*`. Without SMTP, alerts go to the outbox directory as `.eml` files.

## Docker / Compose

`compose.yaml` and `Dockerfile` describe an API + worker on one volume. They are **not yet verified**
(see docs/audit/NT-040-audit.md). Pin the base image by digest before any release.
