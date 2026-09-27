# nodetrust-ci

A GitHub Action that builds an SBOM for an npm project, sends it to a NodeTrust server, and turns the
project's policy verdict into a CI result: annotations, a step summary and an exit code.

> **Status: MVP, not released.** Tested with unit tests, end-to-end tests against a local nodetrust-core, and
> the action's own steps run under `bash -eo pipefail` in an `ubuntu:24.04` container, both the lockfile and
> the Syft path (Syft 1.52.0). It has **not yet run on a real GitHub-hosted runner**.

## Usage

```yaml
permissions:
  contents: read
jobs:
  nodetrust:
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>        # pin to a full commit SHA
        with: { persist-credentials: false }
      - uses: your-org/nodetrust-ci@<sha>   # pin to a full commit SHA
        with:
          api-url: ${{ vars.NODETRUST_API_URL }}
          project-id: ${{ vars.NODETRUST_PROJECT_ID }}
          api-key: ${{ secrets.NODETRUST_API_KEY }}
          mode: monitor
```

A complete example is in [examples/workflow.yml](examples/workflow.yml).

### Inputs

| Input | Default | Notes |
|---|---|---|
| `api-url` | – | `https://…` (plain http only for localhost) |
| `project-id` | – | |
| `api-key` | – | project key with role `ci`, from a secret. Masked in logs. |
| `mode` | `monitor` | used only when the server cannot be reached; otherwise the project's policy decides |
| `working-directory` | `.` | where `package-lock.json` lives |
| `sbom-generator` | `lockfile` | `lockfile` (no downloads) or `syft` |
| `syft-version`, `syft-sha256` | – | required with `syft`: exact version and the tarball's sha256 from the official release |
| `include-dev` | `true` | dev-only packages are included by default (their install scripts run in CI) |
| `timeout-seconds` | `60` | total budget for the API call, retries included |

Outputs: `decision`, `exit-code`, `verdict-path`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | `pass` or `warn`. Monitor mode also ends here when the server is unreachable (UNKNOWN warning). |
| 1 | `gate` or `pending_approval`: a project admin must decide in NodeTrust |
| 2 | configuration error in **both** modes: missing or invalid key, wrong project, invalid SBOM or lockfile |
| 3 | enforce mode and no assessment was possible: timeout, server down, stale or incomplete data |

## What is sent

Only commit SHA, branch, run id, and a minimised CycloneDX SBOM: component name, version, purl,
scope and dependency relations. No source code, file paths, hashes or licences.
See [nodetrust-core docs/data-sent.md](../nodetrust-core/docs/data-sent.md).

## Why the default does not download Syft

NodeTrust is a supply-chain security tool, so it should not pull an unpinned third-party binary into your
build. The default builds the SBOM from `package-lock.json` (v2/v3) with the standard library. With
`sbom-generator: syft`, the action downloads the exact Syft release you name and **verifies its sha256
before running it**. A wrong checksum stops the job before Syft runs. The action asks Syft for CycloneDX 1.6,
because recent Syft releases default to 1.7 and the server accepts 1.4 to 1.6. If Syft's SBOM lacks
dependency relations, they are filled in from the lockfile. Syft also lists your own package as a library
next to its directory root, so the client drops it: the project is the root, not a dependency. For the
checked fixture, the Syft path and the lockfile path produced the same verdict.

## Untrusted pull requests

Pull requests from forks do not receive repository secrets. Skip the job for them (see the `if:` above)
instead of weakening it. Never use `pull_request_target` together with a checkout of the PR's code. A
missing key is a configuration error (exit 2), per policy D06.

## Local use

```bash
cd your-project
python /path/to/nodetrust-ci/src/nodetrust_ci/cli.py sbom --out sbom.json           # just build the SBOM
NODETRUST_API_KEY=... python /path/to/cli.py submit --api-url https://nt.example --project prj_... \
    --commit $(git rev-parse HEAD) --branch main
```

## Development

The client itself needs only the Python standard library (3.11+). The quality gate needs pytest and pyflakes:

```bash
python -m pip install pytest pyflakes   # or reuse nodetrust-core's venv, which already has both
python scripts/check.py     # compile, lint, tests, secret scan, action.yml hygiene (no ${{ }} in run:, pinned uses:)
```
