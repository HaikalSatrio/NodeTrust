# nodetrust-core

NodeTrust tells an npm project maintainer which dependency versions in their build are affected by a
supply-chain incident signal, through which dependency paths, and what the project's policy says to do
about it: pass, warn, gate, or hold for a human decision.

This repository holds the server: registry ingestion, the package graph, risk signals, the API, policy,
alerts and the dashboard. The GitHub Action lives in [`nodetrust-ci`](../nodetrust-ci).

> **Status: MVP in progress, not released.** Scope and policy follow the NT-001 draft (D01–D07), which is
> still **under review**. Several graph and research components are minimal stand-ins until their owners'
> tasks land. See [docs/limitations.md](docs/limitations.md) and the workspace `STATUS.md`.

## What it does

| Area | What you get | Backlog |
|---|---|---|
| npm ingestion | change-feed listener with durable checkpoint; incremental packument fetch with retry, rate limit and size caps | NT-006, NT-007 |
| Risk signals | per-version metadata diff; explainable, versioned heuristic score and tier | NT-009, NT-010 |
| Advisories | OSV import (offline export or API), alias de-duplication, withdrawn handling | NT-011 |
| Projects & API | projects, hashed API keys (`ci` / `admin`), strict per-project isolation | NT-017 |
| SBOM intake | CycloneDX 1.4–1.6 validation and normalisation to exact versions | NT-018 |
| Exposure | baseline report, choke points, drift per push, incident matching with paths | NT-019, NT-020 |
| Policy | monitor/enforce, pre-authorised gates, approvals, one-run overrides, audit | NT-022 |
| Alerts | targeted e-mail (outbox or SMTP), de-duplication, retry, triage | NT-023 |
| Last-known-good | LKG with provenance; draft `overrides` patch, never applied automatically | NT-025 |
| Dashboard | graph, impact paths, blast radius, forecast horizon, alerts, approvals, policy, audit | NT-026 |
| Operations | structured logs, health/metrics, backup/restore with checksum, retention | NT-042 |

## Quick start (offline demo)

Requires Python ≥ 3.11 with the dependencies in `pyproject.toml`. Nothing below touches the network.

```bash
pip install -e ".[dev]"
export NODETRUST_DB_PATH=data/demo.db NODETRUST_SNAPSHOT_MODE=true
nodetrust demo            # seeds synthetic packages, a demo incident and two projects; prints demo keys
nodetrust serve           # http://127.0.0.1:8080/dashboard/  (paste a printed project id + key)
```

On Windows PowerShell, use `$env:NODETRUST_DB_PATH="data/demo.db"` and similar. All demo data is synthetic
(`ntdemo-*` packages, `*-demo` people, `NTDEMO-*` advisories) and every demo verdict is labelled
**simulation** and **offline snapshot**.

## Checks

```bash
python scripts/check.py   # compile + tests + secret scan + dashboard CSP check
```

Tests refuse any non-loopback network connection.

## Configuration

All settings are environment variables prefixed `NODETRUST_` (see [.env.example](.env.example)).
Network access is **off** unless `NODETRUST_ALLOW_NETWORK=true`.

## Documentation

- [Setup](docs/setup.md) · [Architecture](docs/architecture.md) · [API & contract](docs/api.md)
- [What CI sends](docs/data-sent.md) · [Scoring, forecast & validation status](docs/model-and-validation.md)
- [Limitations](docs/limitations.md) · [Runbook](docs/runbook.md) · [Contributing](CONTRIBUTING.md)

## License

Not chosen yet (team decision, tracked in NT-029). A proposal is in `docs/decisions/NT-001-brian-review.md`.
