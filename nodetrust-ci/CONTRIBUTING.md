# Contributing: nodetrust-ci (owner: Brian, reviewer: Haikal)

1. **Standard library only** in `src/`. The action must not add dependencies to the builds it protects.
2. **No `${{ }}` inside `run:` blocks** in `action.yml`. Pass inputs through `env:`. Every `uses:` is pinned
   to a full commit SHA. `scripts/check.py` enforces both.
3. **Secrets**: the API key comes only from `NODETRUST_API_KEY`. It is never an argv parameter and never
   printed except inside `::add-mask::`.
4. **Exit codes and the verdict contract are shared with nodetrust-core** (`docs/contracts.md` there). Change
   them only together with the core repo, after review by both people.
5. **No network in tests.** `tests/` blocks non-loopback sockets. The end-to-end test in `../e2e` talks to a
   local server over 127.0.0.1 only.
6. Fixtures are synthetic (`ntdemo-*`). Do not add real package names or incidents to fixtures.
7. The author does not mark tasks Done. Run `python scripts/check.py`, record evidence, hand over for review.
