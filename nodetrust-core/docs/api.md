# API and verdict contract

All endpoints are JSON. Authenticate with `Authorization: Bearer <token>`. The interactive schema (`/docs`,
`/openapi.json`) is **off by default**; enable it for development with `NODETRUST_EXPOSE_API_DOCS=true`.

After `NODETRUST_AUTH_MAX_FAILURES` failed authentications from one client IP within
`NODETRUST_AUTH_FAILURE_WINDOW_S`, that IP gets `429 rate_limited` (with `Retry-After`) until the window passes.
Behind a reverse proxy set `NODETRUST_FORWARDED_ALLOW_IPS`, otherwise all clients share the proxy's budget.

## Credentials

| Token | Scope |
|---|---|
| Operator (`NODETRUST_ADMIN_TOKEN`) | instance: create projects, curate incidents, import OSV, watchlist, metrics. **No** project actions. |
| Project key, role `ci` | its own project: submit scans, read scans/verdicts/alerts/approvals/LKG |
| Project key, role `admin` | its own project: everything, including policy, keys, approvals, overrides, triage, audit |

A key used on another project's path gets **404** (existence is not revealed). Errors look like
`{"error": {"code": "...", "message": "...", "details": ...}}`.

## Endpoints

| Method & path | Who | Purpose |
|---|---|---|
| `GET /healthz`, `GET /readyz`, `GET /v1/meta` | anyone | liveness, readiness (DB), version/contract |
| `GET /v1/metrics` | operator | counters, fetch-job states, sync status, freshness, feed checkpoint age |
| `POST /v1/projects` | operator | create project → returns the initial **admin key once** |
| `GET /v1/projects` | operator | list projects |
| `POST /v1/incidents`, `GET /v1/incidents?package=&limit=`, `PATCH /v1/incidents/{id}` | operator | curate incidents; only here can evidence become `verified`. The list is newest first, `limit` 1-5000 (default 500), because a real OSV import creates about 220k unverified incidents |
| `POST /v1/intel/osv/records` | operator | upload OSV records (JSON array) |
| `GET/POST /v1/watchlist` | operator | packages the feed follows |
| `GET /v1/graph/stats`, `GET /v1/graph/blast?name=&version=` | any | registry graph size; reverse BFS + heuristic forecast |
| `POST /v1/graph/centrality` | operator | recompute centrality cache |
| `GET /v1/projects/{pid}` | ci/admin | project, current policy |
| `PUT /v1/projects/{pid}/settings` | admin | alert e-mail |
| `GET/PUT /v1/projects/{pid}/policy` | ci read / admin write | versioned policy (every PUT = new version, audited) |
| `GET/POST /v1/projects/{pid}/keys`, `DELETE …/keys/{kid}` | admin | list (no hashes), create (shown once), revoke |
| `POST /v1/projects/{pid}/scans` | ci/admin | submit SBOM → **verdict** |
| `GET /v1/projects/{pid}/scans[/{sid}[/report\|/drift\|/graph\|/verdict]]` | ci/admin | scans, baseline report, drift, graph for dashboard, latest verdict |
| `GET /v1/projects/{pid}/verdicts/{vid}` | ci/admin | a specific verdict |
| `GET /v1/projects/{pid}/alerts`, `POST …/alerts/{aid}/triage` | read / admin | alerts; confirm/reject with note |
| `GET /v1/projects/{pid}/approvals`, `POST …/approvals/{id}` | read / admin | held builds; decide `block`/`allow` with note |
| `GET/POST /v1/projects/{pid}/overrides`, `DELETE …/{oid}` | read / admin | one-run override (≤24 h), revoke |
| `GET /v1/projects/{pid}/lkg?name=&bad=`, `POST …/lkg/patch`, `GET …/lkg/verify` | read / admin | last-known-good, draft pin patch, check next scan |
| `GET /v1/projects/{pid}/audit` | admin | audit log |
| `GET /v1/projects/{pid}/freshness` | ci/admin | freshness of required sources |

## Submitting a scan

```json
POST /v1/projects/{pid}/scans
{ "commit": "<git sha, 7-64 hex>", "branch": "main", "run_id": "<run>.<attempt>", "sbom": { CycloneDX JSON } }
```

The body is limited to `NODETRUST_MAX_SBOM_BYTES` + 4 KiB (413 above). An invalid SBOM gives 422 with
`code: invalid_sbom` and a list of problems. Resubmitting the same SBOM for the same commit reuses the scan
(`scan_reused: true`): no duplicate drift or alerts, but the verdict is re-evaluated.

Packages with an exact version that the graph does not know yet are queued for a targeted registry fetch,
within limits, because scan input is untrusted. `data_quality.coverage` reports `not_in_graph`,
`queued_for_fetch`, `already_queued` and `not_queued`:
- at most `NODETRUST_FETCH_BUDGET_PER_SCAN` new packages per scan;
- no more than `NODETRUST_MAX_PENDING_SBOM_FETCHES` pending across the instance;
- no re-fetch within `NODETRUST_SBOM_FETCH_COOLDOWN_HOURS`;
- names that are not valid npm names are never queued.

Feed/watchlist fetches always run first. Packages that are not queued stay UNKNOWN, not safe.

## Verdict (contract `SCHEMA_VERSION = 2026-09.draft1`)

| Field | Meaning |
|---|---|
| `decision` | `pass` · `warn` · `gate` · `pending_approval` · `unavailable` |
| `assessment` | `ok` or `unknown` (data incomplete/stale or exposure not decidable) |
| `exit_code` | CI mapping (below) |
| `mode`, `policy_version` | policy the verdict was evaluated with |
| `labels` | `simulation`, `offline_snapshot` |
| `data_quality` | `status` (complete/incomplete/stale), coverage, freshness per source, graph snapshot id |
| `findings[]` | per incident: package, versions, tier, heuristic score, evidence status/version, exposure, paths from root, D05 radius, decision, reasons, triage/approval flags |
| `reasons[]` | global reasons (data quality, override applied/rejected, no exposure) |
| `approvals_pending[]`, `override` | held-build approvals created; override applied to this run |
| `drift`, `alerts_raised`, `scan`, `evidence_fingerprint` | context and identity |

### Exit codes (shared with nodetrust-ci)

| Code | When |
|---|---|
| 0 | `pass` or `warn` (monitor mode always ends here, except configuration errors) |
| 1 | `gate` or `pending_approval` |
| 2 | configuration/auth/payload error, in **both** modes (raised by the CI client) |
| 3 | `unavailable` in enforce mode (API unreachable/timeout, stale or incomplete data) |
