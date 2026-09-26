# Live checks against real services (26 Sep 2026)

Offline tests use fakes. This page records the runs against the real services, what they showed, and what
changed because of them. Requests used each tool's own client identity. No project data was sent anywhere.

## NT-002: Docker / Compose / Neo4j

- Clean clone, `.env` from `.env.example` with a generated operator token, `NODETRUST_PORT=18080`.
- `docker compose build`: OK (about 25 s). `up`: API healthy, worker running without network.
- `nodetrust demo` inside the API container seeds the volume. From the host: `/healthz` 200, `/readyz` 200,
  `/dashboard/` 200, `/docs` 404. A project key reads its own scans; a cross-project read is 404.
- Container runs as uid 10001; the root filesystem is read-only (`touch /app/x` fails).
- `--profile neo4j`: Neo4j 5.26.31 Community healthy in about 24 s; `scripts/check_neo4j.py` prints OK.
- Inside the built image, pip resolved newer versions than the development laptop (e.g. FastAPI 0.141,
  Starlette 1.7, networkx 3.7, pytest 9, pyflakes 4). The full suite (177 tests) and pyflakes pass there.
  Starlette warns that `httpx` with its test client is deprecated; tests still pass.
- **Changed:** images pinned by index digest (`python:3.12-slim@sha256:f77ac9e4…`,
  `neo4j:5.26-community@sha256:5eb12ad7…`); API host port configurable (`NODETRUST_PORT`).

## NT-006: npm change feed

- `GET https://replicate.npmjs.com/registry/` → `{"db_name":"registry","engine":"npm-replicate",
  "doc_count":4428178,"update_seq":132801440}`.
- `GET …/registry/_changes?since=<seq>&limit=<n>` → `{"results":[{"seq":int,"id":str,"changes":[…],
  "deleted":true?}],"last_seq":int}`. No `pending`. `limit=10000` accepted.
- **Bug found:** `since=now` (CouchDB style, the old default for a first start) returns **400 Bad Request**,
  so the crawler could never start without a stored checkpoint. **Fixed:** a first start reads `update_seq`
  from the info document and begins there; `start_seq="0"` replays everything. Tests now use the real shape.
- Live run with the fixed code: first poll started at the head without error; a second poll 15 s later saw
  13 real changes and enqueued them; the checkpoint advanced; `sync_status` recorded success.

## NT-007: packument fetch

- The same run fetched 14 real packuments from `https://registry.npmjs.org` through `Fetcher`
  (rate limit 2/s): 14 processed, 0 failed, 0 not found, 0 invalid items, 4,761 versions stored and scored.
- Offline, 1,024 cached packuments were also replayed (`docs/audit/real-data-check.md`).
