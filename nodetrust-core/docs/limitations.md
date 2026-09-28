# Limitations (read before relying on a verdict)

- **npm only**, and `package-lock.json` v2/v3 only in the CI client. pnpm, yarn, Poetry, containers and system
  libraries are out of scope for the MVP (D01).
- **Unknown is not safe.** Packages missing from the graph, inexact versions, missing SBOM relations or
  stale data produce UNKNOWN. Monitor mode warns; enforce mode fails as "assessment unavailable".
- **Scores are heuristics**, uncalibrated. NORMAL is not a certification.
- **Forecasts are simulations** (stand-in), not validated predictions.
- **Advisories are not compromise evidence.** Vulnerability blocking is deferred (D04).
- **The registry graph answers "could pull in"**, not "does pull in". Only the client SBOM gives exact exposure.
- **Graph components are stand-ins** (SQLite + networkx) pending NT-008/012/013. NT-004 now has an
  isolated real-Neo4j spike ([evidence](tasks/NT-004.md)), not a production storage migration.
  NT-005 resolves all observed matching candidates with explicit unresolved/truncated output
  ([semantics](tasks/NT-005.md)); this is not an npm installation or peer constraint solver.
  The runtime graph components are sized for
  thousands of nodes. The 500K-node target is NT-036/NT-043.
- **Live data paths are partly verified.** The npm change feed, packument fetch, the OSV `all.zip` import and
  the OSV API ran against the real services on 26 Sep 2026 (`docs/audit/live-checks.md`). Real npm packuments were also replayed offline from a local
  npm cache (`docs/audit/real-data-check.md`).
  SMTP was tested as a real SMTP/STARTTLS conversation on 127.0.0.1, not against a real mail provider.
  SMTPS on port 465 (implicit TLS) is not supported: use STARTTLS, usually on port 587.
- **Self-host packaging is partly verified.** A clean clone installs and runs `demo`/`serve` from the installed
  package, and `docker compose config` accepts the Compose file. The image itself has not been built, because
  pulling the base image needs network access.
- **Gates act only on pipelines that run the step.** Making it a required check is the repository owner's job.
  NodeTrust never cancels other jobs, rolls back deployments, commits or pushes.
- **Scan evaluation holds the database write lock** for the whole pipeline, including the heuristic forecast
  traversal. At MVP scale (thousands of nodes) this is fine. With a large graph, the heavy reads should move
  outside the write transaction (NT-043 benchmark / NT-036 scaling).
- **Targeted fetches are rate-limited on purpose.** A large SBOM full of packages the graph has not seen fills
  its per-scan budget (default 200). The rest stay UNKNOWN until later scans or the feed bring them in.
- **Failed-auth throttling is in memory** and per process, so a restart resets it. It is not a WAF.
- **D05 radius (option 1, agreed 26 Sep 2026).** Large = A ≥ 100 affected versions, or T ≥ 200 versions in the
  scan and A/T ≥ 20%. The minimum of 200 is an initial MVP value, not validated. The decision also mentions
  escalation across ≥ 2 projects; that rule is not defined precisely yet and is not implemented.
