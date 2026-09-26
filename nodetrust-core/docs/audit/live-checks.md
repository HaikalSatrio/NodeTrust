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

## NT-011: OSV

- `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`: 216,647,962 bytes, MD5 matched the
  server's `x-goog-hash`. 229,416 records, all npm.
- **Bug found:** the import had not finished after more than 10 minutes. There were no indexes on
  `incident (source, source_ref)`, `advisory_alias (advisory_id)`, `advisory (group_id)` or
  `incident (ecosystem, name)`, so every record scanned growing tables.
  **Fixed** with schema revision 3, which also migrates existing databases.
  Now: **75 s**, 229,416 inserted, 0 invalid, 221,614 `MAL-*` incidents (UNVERIFIED, score 80).
  Re-import: 26 s, all 229,416 unchanged, no duplicate incidents.
- **Bug found:** every CI scan loaded and parsed *all* incidents (`match_scan`). With the real import that took
  4.9 s per scan inside the write transaction. **Fixed**: a scan reads only the incidents of its own
  packages. The same scan now takes about 0.02 s. `GET /v1/incidents` gained `limit` and `package`.
- **Bug found:** `nodetrust demo` marked *every* incident in the database as simulation. Run against a real
  database, it would have silently switched off all real incidents for real projects. **Fixed**: the demo
  refuses a database that already has data, and only marks `ntdemo` packages.
- OSV API `POST https://api.osv.dev/v1/query`, live for `lodash`, `event-stream`, `flatmap-stream` and
  `ua-parser-js`. Records were imported and matched by range: `lodash@4.17.20` → 3 advisory groups,
  `4.17.21` → 2, and aliases were grouped. `flatmap-stream` produced `MAL-2025-20690` → one UNVERIFIED
  incident.
- **Changed:** the client now follows `next_page_token` and stops after 50 pages without importing a
  partial result.
- **Observation for the D04 / research review (Haikal):** the 2021 `ua-parser-js@0.7.29` compromise
  appears in OSV only as a GHSA "vulnerability" (`GHSA-pjwm-rvh2-c87w`), not as `MAL-*`. Under D04 (agreed),
  advisories are information only, so no incident is created for that historical attack. This is not
  changed here; it is a policy question.
