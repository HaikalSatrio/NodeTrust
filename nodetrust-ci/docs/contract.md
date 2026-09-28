# NT-003 shared contract

The review candidate for package identity, scan input, verdicts and exit codes
is [the shared contract](../../nodetrust-core/docs/contracts.md).
The wire version stays `2026-09.draft1`; this task does not change client behavior.

Core's `tests/test_contracts.py` checks this client's actual lockfile output,
version/exit-code mapping and summary against the real in-process API.
Run it from `nodetrust-core` after installing `.[dev]`. The client retains
standard-library-only runtime dependencies.

Brian reviews the shared contract and these compatibility checks before NT-003
can be marked Done. Any later breaking change must update both components.
