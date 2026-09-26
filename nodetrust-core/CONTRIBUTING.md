# Contributing: nodetrust-core

Read this before changing anything. It is the NT-040 workflow in practice.

## Ground rules

1. **No network.** Do not add code paths that reach the internet outside `registry/transport.py`
   (gated by `NODETRUST_ALLOW_NETWORK`). Tests must pass offline; `tests/conftest.py` blocks
   non-loopback sockets. Never "just check" an endpoint from a test.
2. **No fabricated research.** Do not invent incident timelines, T0 values, ground truth, accuracy numbers
   or advisory ids. Fixtures are synthetic and must look synthetic (`ntdemo-*`, `NTDEMO-*`, `*-demo`).
3. **The reviewer approves.** The author implements, tests and documents, but does not mark a task Done, approve a
   merge, verify evidence, or change policy defaults. Status moves to Review; a teammate reviews.
4. **Contract changes need both people.** Anything in `src/nodetrust/contracts/`, the verdict body
   (`pipeline.py`), `SCHEMA_VERSION`, or exit codes affects `nodetrust-ci`. Change both repos together
   after review.
5. **One task per branch/worktree.** Keep diffs inside the owning area below.

## Ownership (from the backlog; either person may review the other's area)

| Area | Path | Owner | Notes |
|---|---|---|---|
| Contract (NT-003) | `contracts/` | Haikal | Draft written by Brian so his tasks can integrate |
| Graph store, BFS, centrality (NT-004/008/012/013) | `graph/` | Haikal | SQLite/networkx stand-ins |
| Resolver (NT-005) | `semver.py` | Haikal | Semver + range stand-in |
| Forecast (NT-015/016) | `forecast/` | Haikal | Heuristic stand-in, labelled unvalidated |
| Matching (NT-021) | `exposure/matching.py` | Haikal | Stand-in |
| Feed, fetch (NT-006/007) | `registry/` | Brian | |
| Diff, scoring (NT-009/010) | `risk/` | Brian | |
| OSV (NT-011) | `intel/` | Brian | |
| API, auth (NT-017) | `api/` | Brian | |
| SBOM, overlay, drift (NT-018/019/020) | `sbom/`, `exposure/` | Brian | |
| Policy, approvals, overrides (NT-022) | `policy/` | Brian | Encodes NT-001 (D01–D07) |
| Alerts, triage (NT-023) | `alerts/` | Brian | |
| LKG (NT-025) | `lkg/` | Brian | |
| Dashboard (NT-026) | `dashboard/` | Brian | Vanilla JS, CSP `'self'` only |
| Observability, ops (NT-042) | `obs/`, `ops.py`, `cli.py` | Brian | |

## Commands

```bash
python scripts/check.py                  # the quality gate, must pass before review
python -m pytest tests/test_policy.py    # a single area
python scripts/make_demo_fixtures.py     # regenerate synthetic demo fixtures
```

## Definition of Done (from the plan)

Acceptance proven, relevant tests pass, work reviewed by the teammate, docs/contract updated,
evidence and commit recorded, no security blocker or unsupported claim. **Stopping work is not Done.**

## Task brief template

Use `docs/tasks/TEMPLATE.md` when planning a slice of work.
