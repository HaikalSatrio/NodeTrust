# Contract between nodetrust-core and nodetrust-ci

`SCHEMA_VERSION = "2026-09.draft1"` (`src/nodetrust/__init__.py`, `nodetrust-ci/src/nodetrust_ci/__init__.py`).
The client warns when the server reports a different version. Change both sides in the same review
(CONTRIBUTING.md rule 4).

Shared elements:

1. **Scan submission body**: `commit`, `branch`, `run_id`, `sbom` (CycloneDX 1.4–1.6, minimised).
2. **Verdict fields the client reads**: `schema_version, decision, assessment, mode, policy_version, labels,
   data_quality.status, data_quality.graph_snapshot, scan.{commit,branch,scan_id}, scan_reused, drift,
   override, findings[].{package,versions,tier,risk_score,evidence_status,exposure,decision,paths,
   is_simulation,reasons}, reasons[].message, approvals_pending`.
3. **Exit codes**: 0 pass/warn · 1 gate/pending_approval · 2 configuration error · 3 unavailable (enforce).
4. **Error body**: `{"error": {"code", "message", "details"}}`. The client treats 401/403/404/413/422 as
   configuration errors (no retry) and 429/5xx/timeouts as unavailable (retry within the 60 s budget).

Draft status: this contract is part of NT-003 (owner Haikal) and is not agreed yet.
