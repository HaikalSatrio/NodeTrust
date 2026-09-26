# Scoring, forecast and validation status

## Risk score (NT-010): heuristic, not a probability

Each new version is diffed against the previous version of the same package (NT-009). Rules in
`src/nodetrust/risk/rules/rules-v1.json` add weights:

| Rule | Weight | Notes |
|---|---|---|
| same_version_integrity_changed | 60 | more than one hash seen for one published version |
| install_script_added | 35 | pre/post/install hook newly present |
| all_maintainers_replaced | 25 | no previous maintainer remains |
| publisher_new_to_package | 20 | publisher never published this package before |
| dependency_on_new_package | 20 each, cap 40 | added dependency first published ≤ 30 days before |
| repository_changed | 15 | repository URL changed |
| maintainer_added | 10 each, cap 20 | |
| dependency_added | 5 each, cap 15 | |

`score = clamp(round(sum), 0, 100)` as an integer. Tiers: NORMAL 0–40, WATCH 41–70, INVESTIGATE 71–85,
CRITICAL ≥ 86. The weights are a **draft proposal** and have not been calibrated against any data. A hash
that differs between two different versions is normal and never scored. Added dependencies whose package is
not in the graph are reported as "not assessed" (weight 0), not as safe.

Crawler scores ≥ 41 create **unverified** incidents. The first ingest of a package scores its history
without raising signals. An OSV `MAL-*` report creates an unverified incident with score 80 (INVESTIGATE).
That value is also a proposal.

## Forecast: heuristic stand-in, **not validated**

`src/nodetrust/forecast/` exists so that alerts and the dashboard can carry a timeline field. The real
engine is NT-015, and validation is NT-014/NT-016 (owner: Haikal). Every output says
`kind: heuristic_simulation`, `validated: false`, and its low/high band is a fixed ×0.5/×2 multiplier,
**not a confidence interval**. Do not quote these numbers as predictions.

## Validation status

| Claim | Status |
|---|---|
| Tier boundaries, policy matrix, D05 thresholds | unit-tested (behaviour, not accuracy) |
| Scoring weights | uncalibrated draft |
| Forecast | not validated; stand-in only |
| Historical incident replay | not started (NT-014/016) |
| Live npm feed endpoint and response shape | verified live 26 Sep 2026 (`docs/audit/live-checks.md`) |
| OSV API query path and `all.zip` import | verified live 26 Sep 2026 (`docs/audit/live-checks.md`) |
