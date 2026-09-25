# Real npm metadata check (NT-007, NT-009, NT-010)

Date: 26 Sep 2026. Run fully offline on a development machine. Needs review by Haikal.

## Method

`python scripts/real_data_check.py OUT_DIR` takes the **full packuments that npm itself had cached** on
the machine (`npm-cache/_cacache`), checks each body against its cache integrity hash, and runs the normal
`nodetrust ingest` path on them: normalise → graph → diff every version → score with `rules-v1`.
No request leaves the machine.

The sample is whatever this machine happened to install: 1,024 packages, mostly popular ones.
It has **no ground truth**. It measures robustness, speed and alert volume. It says nothing about
detection accuracy and must not be quoted as a false-positive rate for npm as a whole.

## Results

| Measure | Value |
|---|---|
| Packuments | 1,024 (all passed the integrity check; 0 rejected as a whole) |
| Versions scored | 291,040 (each historical version once) |
| Ingest time | 103 s end to end on a laptop, after the fix below |
| Normaliser item rejects | 22 dependency entries in 10 old packuments (e.g. `equire('express'`, `../serve-static`), all correctly dropped |
| NORMAL / WATCH | 99.73 % / 0.26 % |
| INVESTIGATE / CRITICAL | 15 / 3 versions |

Rules fired (versions / packages): maintainer_added 12,038 / 461 · dependency_added 7,138 / 468 ·
dependency_target_not_assessed 4,541 / 365 · repository_changed 3,569 / 570 · publisher_new_to_package
1,093 / 506 · all_maintainers_replaced 593 / 58 · dependency_on_new_package 304 / 127 ·
install_script_added 237 / 32.

## Bug found and fixed: quadratic diff (NT-009)

Before this run, each version's diff re-read and re-sorted the package's whole history.
One `react` packument (2,886 versions) took **595 s**. That time was spent inside the fetcher's write
transaction, so every other SQLite writer waited, including CI scan submissions. Any SBOM that names a
large package could trigger that fetch.

`diff_versions()` now sorts once per package. `react` takes 1.1 s. On 120 real packages (6,448 versions)
the new code returns **identical deltas** to the old code (commit `perf(NT-009)`).

## Observations for the weights review (NT-010, Haikal)

These are observations only. No weight was changed.

1. **Legitimate name transfers look like account takeovers.** Most INVESTIGATE versions are the first
   release after a package name changed hands. Examples: `react-dom@0.14.0-beta1`, `playwright@0.9.1`,
   `tsx@2.0.0`, `react-router@0.0.0`, `qs@1.0.0`, `cookie@0.1.3`. The signals (all maintainers replaced,
   new publisher, repository changed) match a takeover exactly. Neither metadata nor the rules can tell the
   two apart. Worth deciding if a large version jump (new major or reset to 0.x/1.0.0) together with a
   repository change should add context, not lower the score.
2. **Prerelease lines use the wrong base.** `rolldown@0.5.0-canary-…` scored 100 because its "previous
   version" by semver precedence belongs to an unrelated earlier line. Possible options: compare a
   prerelease only within its own line, or compare against the previous version by publish time.
3. **`dependency_target_not_assessed` fires on 365 packages** in this sample, because the dependency
   targets were not ingested. On a real crawler, this depends on watchlist coverage. The weight should
   assume the graph is often partial.
4. Alert volume. If every version of these 1,024 packages were published today, about 0.26 % would be
   WATCH and 18 versions would reach INVESTIGATE or CRITICAL. Under the NT-001 draft, those 18 would be
   e-mailed only to projects that actually depend on the version.

## What this does not verify

- The live npm change feed and packument endpoint (NT-006, network).
- Real OSV data (NT-011, network).
- Whether the rules catch real compromises. That needs labelled incidents (NT-014/016, research).
