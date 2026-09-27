# NT-003: package identity and core/CI data contract

**Owner: Haikal. Reviewer: Brian. Status: review candidate, 27 September 2026.**
This specifies Brian's existing wire contract and reference shapes for graph adapters.

## Version and compatibility

`SCHEMA_VERSION = "2026-09.draft1"` remains identical in core and CI.
No wire fields, enum meanings, exit codes or policy defaults change in this task.
The draft label stays until team review. Breaking changes require a new version
on both sides, updated fixtures, a migration note and review by Haikal and Brian.
Persisted verdicts retain their original version. The current client only warns
on a version mismatch; no automatic migration or negotiation is claimed.

Machine-readable definitions live in `src/nodetrust/contracts/schema.json`
(JSON Schema Draft 2020-12). `contract_schema(name)` selects a local definition
without network access. `jsonschema[format-nongpl]` is development-only; the
client remains stdlib-only. Use a format checker to enforce date-time fields.

Definitions: package_id, package_record, dependency_edge, sbom, scan_submission,
scan_identity, finding, verdict, error.

Package/edge reference objects and scan envelopes are closed. Responses allow
optional additions; existing required fields and types must stay compatible.
Null and missing are different unless explicitly allowed by the definition.

Schemas are checked in contract tests, not automatically inserted into production
request handling. Existing API and SBOM validators remain in charge. Package/edge
reference records are interchange designs for later adapters, not new endpoints
or a storage migration.

## Package identity

Identity is **(ecosystem, name, exact version)**.

| Field | Contract |
|---|---|
| ecosystem | npm for MVP; always part of identity |
| name | Canonical lowercase npm name, including @scope/name; maximum 214 characters |
| version | Exact semver, including prerelease/build metadata; no ranges, tags, null or whitespace |

Registry/SBOM producers normalize names; PackageId is a value container, not a
complete validator for arbitrary external input. The current resolver permits
a leading v. Preserve full version text (including v and build metadata) across
producers. Semver precedence may ignore build metadata, but identity does not.
Changing that behavior belongs to a joint NT-005 migration decision.

Example key: `npm:@ntdemo/logger@1.2.3-beta.1+demo`.
PURL: `pkg:npm/%40ntdemo/logger@1.2.3-beta.1%2Bdemo`.
Split keys at the last @; keep the scoped name intact. PURL qualifiers/subpaths
do not contribute to MVP identity. An unresolved version never becomes a guessed
package-version node.

## Metadata and provenance

The package_record reference shape contains identity and these fields:

| Field | Meaning |
|---|---|
| integrity | Observed SRI, legacy sha1hex-... or null; not proof that tarball bytes were verified |
| published_at | Registry publication timestamp with timezone, or null when unknown |
| publisher | Name or null; omit email addresses |
| maintainers | Unique names; empty means none observed, not proof that nobody owns it |
| first_seen / last_seen | Collector observation timestamps with timezone |
| source | Provenance label such as registry or synthetic-demo |

The existing database stores maintainers as maintainers_json and identity in
three columns. Registry timestamp strings are currently retained as raw input:
an adapter must report/normalize invalid timestamps before exporting a conforming
reference record. Never fabricate publication time from observation time.

The store retains integrity observations. Hash changes across different versions
are not automatically suspicious; a same-version change is a review signal, not
verified compromise. SBOM intake drops package hashes/authors. Its sbom_sha256
identifies the submitted document, not a tarball.

## Dependency direction and resolution

**dependent —DEPENDS_ON→ dependency**. Example: ntdemo-app@1.0.0 → ntdemo-leaf@2.0.0.
Reverse blast-radius traversal starts at leaf and finds app. The project root is
a scan-local reference, not a package-version node or a radius-count member.

Reference edge fields: from, to, relation, declared_spec, kind, resolution.
kind is prod, optional or peer.

| Resolution | Target version | Meaning |
|---|---|---|
| client_resolved | Exact, required | Observed in the client's lockfile/SBOM |
| registry_possible | Exact, required | Candidate admitted by a registry declaration, not proof of installation |
| unresolved | null | Preserve declaration without inventing an exact target |

Registry storage keeps dst_name/spec/kind and resolves candidates at query time.
SBOM edges connect local bom-refs. The reference schema expresses their common
meaning without claiming identical persistence formats. Aliases retain the
declaration but identity uses the actual target package. Cycles are valid input;
traversal bounds and truncation belong to NT-005/012.

## Scan / SBOM

Request: commit, branch, optional nullable run_id, sbom.
The API normalizes commit case/whitespace before checking a 7–64 character hex
SHA; the schema describes normalized input. GitHub run_id combines
GITHUB_RUN_ID.GITHUB_RUN_ATTEMPT; a new attempt is a new run.

SBOM envelope: CycloneDX JSON, specVersion 1.4–1.6. This schema covers the supported
envelope, **not the full CycloneDX specification**. parse_cyclonedx owns graph
reference/coverage checks. The default client uses lockfile v2/v3; Syft is
optional per D01.

- Exact npm versions remain exact. Missing/range versions are unresolved.
- Non-npm components are out_of_scope, not npm package-version nodes.
- Missing root relations, unresolved npm components or unreachable npm components
  make coverage incomplete; incomplete data does not imply safety.
- Count unique package versions, not paths, edges or the project root.
- Package absence in the registry graph is UNKNOWN even with an exact client
  version. It neither creates a fake identity nor proves safety.

## Verdict / errors

The verdict definition covers pipeline.py output: version, scan identity, policy
version, mode, decision/assessment, data quality, findings, reasons, labels,
approvals, override, timestamp, drift and reuse status.

Keep tier/score, evidence_status, exposure, data_quality and decision separate.
Scores are heuristics, not probabilities or evidence verification. Exposure is
exposed/not_exposed/unknown; evidence is unverified/verified/rejected. Quality is
complete/incomplete/stale. Assessment is ok/unknown.

Finding versions are display/evidence strings and may contain unresolved values
including ?. Validate before creating a PackageId. Simulation/offline labels stay
visible. Forecast validation is outside this task. D05 retains option 1:
A >= 100 OR (T >= 200 AND A/T >= 20%); unknown radius requires review.

Exit codes: 0 pass/warn; 1 gate/pending_approval; 2 configuration/auth/payload
error; 3 unavailable in enforce mode. The schema checks decision/exit consistency.
Unavailable means unknown, not malware. Transport failure continues with UNKNOWN
in monitor mode and exits 3 in enforce mode.

Errors: `{"error": {"code": "...", "message": "...", "details": ...}}`.
Details are optional. Configuration responses 401/403/404/413/422 are not retried;
retryable server/transport failures stay within the client's 60-second budget.

## Fixtures and review

Synthetic reference fixture: `fixtures/contracts/nt003.json` (scoped identity,
unknown metadata, resolved edge, submission and error). No real incident claims.

Run from nodetrust-core:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/test_contracts.py
python scripts/check.py
```

Tests cover positive/negative records, exact-version/PURL round trips, registry
edge direction, client/server version and all exit codes, and client-generated
SBOM → real in-process API → client summary for clean/incomplete/nonempty findings.

Brian's review:
1. Agree identity, version-text preservation, metadata nulls and edge direction.
2. Check reference shapes against the next graph adapter.
3. Review schema coverage, compatibility and core/CI test evidence.
4. Record approval before moving NT-003 from Review to Done.

Actual human hours are recorded separately; passing tests do not replace review.
