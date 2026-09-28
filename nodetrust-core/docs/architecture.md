# Architecture

```
                 npm replicate _changes            npm registry            OSV (API or all.zip)
                          │ (gated)                     │ (gated)              │ (file import = offline)
                          ▼                             ▼                      ▼
                ┌──────────────────┐  jobs   ┌────────────────────┐   ┌──────────────┐
                │ feed listener    │───────▶│ fetcher/normaliser │   │ OSV adapter  │
                │ NT-006 checkpoint│         │ NT-007             │   │ NT-011       │
                └──────────────────┘         └─────────┬──────────┘   └──────┬───────┘
                                                        ▼                      │
                                       ┌──────────────────────────────┐        │
                                       │ package-version graph (NT-008)│◀──────┘ advisories
                                       │ diff NT-009 → score NT-010    │
                                       │ → crawler signals (incidents)│
                                       └──────────────┬───────────────┘
                                                      │
  nodetrust-ci ──CycloneDX──▶ API (NT-017) ──▶ scan (NT-018) ──▶ drift (NT-020)
                                                      │
                                                      ▼
                         incidents × exact versions → findings (NT-021 stand-in)
                                                      │  paths, D05 radius, heuristic forecast
                                                      ▼
                                    policy engine (NT-022, D04 matrix) → verdict
                                          │                │                │
                                   approvals/overrides   alerts (NT-023)   CI exit code
                                          │                │
                                        audit log      outbox / SMTP
```

## Processes

- **API** (`nodetrust serve`): FastAPI app, sync endpoints in a thread pool; dashboard served as static
  files under `/dashboard/`.
- **Worker** (`nodetrust worker`): feed poll + fetch (only when network is allowed), then alert dispatch.
- **Storage**: one SQLite file in WAL mode (D02: SQLite + one worker for the MVP). Writers are serialised
  in-process; the scan pipeline runs in a single transaction.

## Key invariants

| Invariant | Where it is enforced | Test |
|---|---|---|
| Checkpoint never ahead of accepted work | `registry/feed.py` (jobs + checkpoint in one transaction) | `test_ingest.py::test_crash_before_commit…` |
| Job done only after graph write | `registry/fetch.py` | `test_graph_write_failure_rolls_back…` |
| Replays are idempotent | graph upserts, job upsert, scan identity (project, commit, SBOM hash) | `test_fetch_writes_graph_and_is_idempotent`, `test_scan_is_idempotent…` |
| A key only sees its project | `api/auth.py::require_project` | `test_project_isolation_and_roles` |
| Scores never gate on their own | `policy/engine.py` | `test_s3_unverified_critical_never_gates…` |
| Advisory ≠ compromise | incidents vs advisories are separate; MAL-* → unverified incident | `test_osv.py` |
| Unknown ≠ safe | exposure/radius/coverage UNKNOWN paths | `test_s6…`, `test_s7…`, `test_missing_relations…` |
| Simulations never mix with real projects | `include_simulations` policy flag | `test_s11…` |
| Secrets never logged | `obs.redact` on every log record | `test_logs_never_contain_keys` |

## Identity and direction

- Package identity: `(ecosystem, name, version)`, version always exact.
- `DEPENDS_ON`: dependent → dependency. Blast radius walks edges in reverse.
- The registry graph answers "could pull it in" (declared spec admits version). The client SBOM answers
  "does pull it in" (exact versions and relations). They are never mixed.

## Stand-ins (to be replaced by the owners' tasks)

| Stand-in | Replaced by |
|---|---|
| SQLite graph store (`graph/store.py`) | NT-004/NT-008 (Neo4j decision) |
| Reverse BFS (`graph/blast.py::reverse_bfs`) | NT-012 |
| networkx centrality (`graph/centrality.py`) | NT-013 |
| Semver/range matching (`semver.py`) | NT-005 resolver |
| Heuristic forecast (`forecast/`) | NT-015 (+ validation NT-014/016) |
| Incident matching (`exposure/matching.py`) | NT-021 |
| Contract (`contracts/`) | NT-003 |
