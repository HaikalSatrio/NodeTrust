# Runbook NT-042 (MVP, self-host)

## Health

| Check | How | Healthy |
|---|---|---|
| Liveness | `GET /healthz` | `{"status":"ok"}` |
| Readiness | `GET /readyz` | 200, schema revision shown; 503 = DB unavailable |
| Freshness | `GET /v1/metrics` (operator) → `freshness.sources` | each required source `fresh` (≤ 24 h) |
| Feed lag | `/v1/metrics` → `feed.npm.checkpoint_age_s`, `sync["feed:npm"].detail.pending_upstream` | age small, pending trending down |
| Fetch backlog | `/v1/metrics` → `fetch_jobs` | `pending` bounded, `failed` investigated |
| Alert delivery | `/v1/metrics` → `alerts` | no growing `failed`; `no_recipient` means no project e-mail |

## Logs

One JSON object per line on stderr: `ts, level, logger, event, correlation_id, …fields`.
`correlation_id` is the request id (API), the scan id (pipeline), `fetch:<package>:<seq>` (crawler) or the
alert id (delivery). Credentials are redacted before writing. If you ever see a key in a log, treat it as an
incident: revoke the key (`DELETE /v1/projects/{pid}/keys/{kid}`) and report the log line.

## Common situations

- **Verdicts say "stale"**: check `sync_status` in `/v1/metrics`. If the feed has `last_error`, fix
  connectivity, then restart the worker. It resumes from the stored checkpoint, and replaying is safe.
- **A package is "not in graph"**: the scan queued a targeted fetch. It is fetched on the next worker tick
  (network must be enabled). It stays UNKNOWN until then.
- **Build held (`pending_approval`)**: a project admin decides in the dashboard (Alerts & approvals) or via
  `POST /v1/projects/{pid}/approvals/{id}`. Re-run the CI job.
- **Emergency bypass**: a project admin creates an override for the scan (reason required, ≤ 24 h, one run).
  It is audited, and findings stay visible.
- **CI gets `429 rate_limited`**: that client IP had too many failed authentications (wrong/revoked key). Fix the
  secret and wait for `Retry-After`. If *all* clients get 429 behind a proxy, set `NODETRUST_FORWARDED_ALLOW_IPS`
  to the proxy address. Rising `auth_failures` in `/v1/metrics` can mean someone is probing keys.
- **Scans report many `not_queued` packages**: the targeted-fetch budget was reached (a large new SBOM, or a
  flood). Pending jobs are in `/v1/metrics` → `fetch_jobs`. Raise the budget deliberately, or let the worker
  drain the queue; feed/watchlist jobs are always served first.

## Restart

Stop the API and worker, start them again. Both are stateless apart from SQLite, and the feed resumes from
its checkpoint.

## Backup and restore

```bash
nodetrust backup backups/nodetrust-$(date +%F).db     # online-consistent copy + .sha256
nodetrust restore backups/<file>.db --verify-only       # checksum + integrity_check
# stop API and worker, then:
nodetrust restore backups/<file>.db --yes               # previous DB is kept aside, never deleted
```

## Retention

`nodetrust purge [--days N]` (default `NODETRUST_RETENTION_DAYS=90`) removes finished fetch jobs and
delivered outbox files only. Scans, verdicts, alerts and the audit log are **kept** until the team agrees
their retention period (open decision).
