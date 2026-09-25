# NT-040: Code audit and development workflow (2026-09-25)

**Status: Review** (needs Haikal's review; not Done).

## 1. Inventory of existing code

- A search of `C:\Users\Brian\Documents` for anything named `nodetrust` found **no existing NodeTrust code**
  on this machine before this session.
- The backlog says "kode belum diaudit" and the Notion documents describe code examples (Build guide).
  **If Haikal has code elsewhere (another machine, a GitHub repo), it has not been audited.** It must be
  compared with this implementation before either is treated as the baseline. (Open item.)

## 2. What exists now

| Repo | Contents | Tests |
|---|---|---|
| `nodetrust-core` | Python 3.12 / FastAPI / SQLite. Brian's MVP tasks + labelled stand-ins for Haikal's graph/forecast tasks | 148 passing (139 + 9 hardening, 2026-09-26) |
| `nodetrust-ci` | stdlib-only GitHub Action client + composite `action.yml` | 19 passing |
| `e2e/` (workspace) | CI client (subprocess, real HTTP on 127.0.0.1) against a running core with demo data | 6 passing |

Baseline command: `python scripts/check.py` in each repo (compile, tests, secret scan, CSP/action hygiene).
All tests run offline and block non-loopback sockets.

## 3. Gaps and unverified items

| Item | Why open | Owner / next step |
|---|---|---|
| npm change-feed endpoint + response shape | needs network; parser accepts int/str seq and tolerates missing `last_seq` | Brian: verify against npm docs, add a recorded fixture |
| Real packument fixtures ("fixture metadata nyata", NT-007) | offline; only synthetic packuments used | Brian: capture 3–5 real packuments (large, scoped, deprecated) as fixtures |
| OSV API / real OSV export | tested with fakes and a synthetic zip | Brian: import the real npm `all.zip` once, check timing |
| SMTP delivery | outbox tested; SMTP path not exercised | Brian |
| Dockerfile / Compose | Docker daemon not running; images cannot be pulled offline | Brian (NT-002) |
| Clean-machine setup | `pip install` needs network; offline wheel build verified (53 files incl. dashboard + rules) | Brian/Haikal: run `docs/setup.md` on a clean machine |
| GitHub runner run of the action | not possible locally | Brian (NT-024): run `examples/workflow.yml` in a test repo |
| Action SHA pinning in CI workflows | SHAs cannot be looked up offline | Brian (NT-044): pin `actions/checkout`, `actions/setup-python` |
| Graph stand-ins | Neo4j/GDS decision pending | Haikal (NT-004/008/012/013) |
| Forecast / validation | stand-in only, labelled `validated: false` | Haikal (NT-014/015/016) |

## 4. Development workflow set up

- `CONTRIBUTING.md` in both repos: ground rules (no network, no fabricated research, humans approve, contract changes
  need both people), folder ownership, commands, Definition of Done.
- `docs/tasks/TEMPLATE.md`: task brief for a ~3 h work session, with a record section (Jam Aktual, evidence).
- Quality gates: `scripts/check.py` in both repos, wired into `.github/workflows/ci.yml`.

## 5. Calibration (Jam Aktual)

The acceptance asks for actual hours on two early tasks. Hours were not measured during this session, so the
backlog's human-hour estimates cannot be calibrated from it. **Jam Aktual is left empty on purpose.** Proposal:
record the human **review** hours for NT-017 (API) and NT-006 (feed) as the two calibration tasks, and compare
them with the review share (≈20%) of the plan.

## 6. Self-review follow-up (2026-09-26)

Probed as an attacker holding a valid `ci` key:

| Finding | Impact | Fix | Test |
|---|---|---|---|
| One SBOM queued **3001** registry fetch jobs, including a traversal-style name (`../../admin`) | Amplification against npm and starvation of feed/watchlist fetches once network is on. No SSRF: the registry host is fixed. | Invalid npm names become out-of-scope. Per-scan budget (200). Global ceiling on pending SBOM jobs (5000). 24 h cooldown per package. Feed jobs outrank SBOM jobs. Already-pending jobs cost no budget. | `tests/test_hardening.py` |
| `/docs` + `/openapi.json` public | Information exposure | Off by default (`NODETRUST_EXPOSE_API_DOCS`) | `test_api_docs_closed_by_default` |
| No limit on failed authentication | Log/DB noise, credential stuffing | Per-IP sliding-window throttle → 429. Proxy-aware via `NODETRUST_FORWARDED_ALLOW_IPS`. | `test_failed_auth_is_throttled…` |
| Mixed timestamp formats (`datetime('now')`) | Inconsistent audit/ordering | ISO-8601 `Z` everywhere | existing suite |

Schema revision 1 → 2 (`fetch_job.priority`), migrated automatically on start (`test_old_database_is_migrated`).

Still open, and deliberately left for NT-041 (Haikal's security audit): an independent review of auth, parser
limits, CI trust boundary and secret handling. This follow-up is not a substitute for it. The long write
transaction during scan evaluation is documented in `docs/limitations.md` (NT-043/NT-036).

## 7. Pre-review pass (2026-09-26, later)

Work done so the handover to Haikal is complete. Each change is a separate commit on `brian/mvp-review`.

| Check | Found | Fix | Evidence |
|---|---|---|---|
| Clean clone + fresh venv + `pip install .` (offline, `--no-index`) | `nodetrust demo` crashed from an installed package (fixture path resolved inside site-packages). The Docker image would have hit the same bug. | Falls back to `./fixtures/demo`. Otherwise exits 2 with a hint. | `test_installed_demo_cli_*`; install/serve smoke from the clone |
| e2e suite placement | `e2e/` sat outside both repos, so a reviewer would never receive it | Moved to `nodetrust-core/e2e/`. `check.py` runs it when `nodetrust-ci` is cloned alongside. | `check.py` output |
| SMTP over a real SMTP conversation (loopback) | `starttls()` without a context does **not verify the certificate**, so a MITM could collect the SMTP password | Verifying context by default. `NODETRUST_SMTP_CA_FILE` for relays on a private CA. | `tests/test_smtp.py` (the untrusted-cert test fails against the old code) |
| Real npm metadata (1,024 packuments from the local npm cache) | First ingest of a large package was quadratic. `react` took 595 s inside the fetcher's write transaction, blocking CI submissions. | `diff_versions()`: one sort per package, 1.1 s. Identical deltas on 6,448 real versions. | `docs/audit/real-data-check.md`, `test_batched_diff_is_fast_on_long_histories_and_matches_single` |
| Keyboard-only walkthrough of the dashboard (headless Edge, demo data) | Focus lost after login/logout. Tabs had no arrow keys or `aria-controls`. Graph label ignored (no role). `aria-selected` on plain rows. Favicon 404. | Fixed. All controls were already reachable and had a focus ring. | commit `fix(NT-026)`. A screen-reader pass by a human is still needed. |
| `docker compose config` | valid | – | – |

Line endings are pinned to LF (`.gitattributes`) so Windows and Linux checkouts produce identical files.
