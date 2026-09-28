# NodeTrust

npm dependency exposure, risk signals, policy and alerting, plus a GitHub Action that submits a project's
SBOM and applies the verdict. Team: Haikal and Brian.

```
NodeTrust/
├── nodetrust-core/   server: registry ingestion, graph, risk, API, policy, alerts, dashboard (Python)
└── nodetrust-ci/     GitHub Action + standard-library client that submits SBOMs and applies the verdict
```

## Run the checks

```bash
cd nodetrust-core
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python scripts/check.py                           # compile, lint, tests, e2e with nodetrust-ci, secret scan
cd ../nodetrust-ci && python scripts/check.py     # same venv
```

Setup, Docker and Neo4j: `nodetrust-core/docs/setup.md`. Limitations: `nodetrust-core/docs/limitations.md`.
Review guide for the current branch: `nodetrust-core/docs/review/HANDOVER-haikal.md`.

## Using the action

The action lives in a subfolder, so reference it with its path and a full commit SHA:

```yaml
- uses: HaikalSatrio/NodeTrust/nodetrust-ci@<full-commit-sha>
```

See `nodetrust-ci/README.md` and `nodetrust-ci/examples/workflow.yml`.
