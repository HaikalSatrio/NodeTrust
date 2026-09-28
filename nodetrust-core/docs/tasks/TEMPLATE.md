# Task brief (NT-040 template)

Fill this in before a ~3 h session (20 min prep · 100 min implementation · 45 min test/review · 15 min record).

- **Task code / slice:** NT-0xx: one sentence on the slice (not the whole task)
- **Acceptance for this slice:** copy the relevant lines from the backlog "Kriteria Selesai"
- **Files in scope:** e.g. `src/nodetrust/alerts/`, `tests/test_api.py`
- **Files it must not touch:** contracts, other owner's areas, CI config (unless the task says so)
- **Dependencies / mocks:** what is real, what is a stand-in (mocks help preparation, never pass an integration gate)
- **Fixtures:** which fixtures prove acceptance; synthetic only
- **Test command:** `python scripts/check.py` (plus the focused test file)
- **Forbidden:** network calls, invented research data, marking Done, weakening tests to pass
- **Reviewer:** the other person; automated review is advisory only

## Record after the session

- Actual human hours (Jam Aktual): measured, not estimated
- Evidence: commit/branch, test output, screenshots
- Open questions / decisions needed
- Next slice
