"""SQLite storage (MVP: one file, one worker, D02 / Build guide).

Graph tables are a stand-in for the Neo4j store of NT-004/NT-008 (owner: Haikal);
application tables (projects, keys, scans, policy, alerts, audit) belong to
NT-017 and friends. Every application row carries project_id so isolation can be
enforced in one place (the API layer) and tested.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_REVISION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- ---------------------------------------------------------------- graph (NT-008 stand-in)
CREATE TABLE IF NOT EXISTS pkg (
  ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  maintainers_json TEXT NOT NULL DEFAULT '[]',
  dist_tags_json TEXT NOT NULL DEFAULT '{}',
  registry_modified TEXT, fetched_at TEXT, source TEXT NOT NULL DEFAULT 'registry',
  PRIMARY KEY (ecosystem, name));

CREATE TABLE IF NOT EXISTS pkg_version (
  ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
  integrity TEXT, published_at TEXT, publisher TEXT,
  maintainers_json TEXT NOT NULL DEFAULT '[]',
  install_scripts_json TEXT NOT NULL DEFAULT '[]',
  repository TEXT, deprecated INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'registry',
  PRIMARY KEY (ecosystem, name, version));

-- DEPENDS_ON: (ecosystem,name,version) -> dst_name with a declared spec.
CREATE TABLE IF NOT EXISTS dep_edge (
  ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
  dst_name TEXT NOT NULL, spec TEXT NOT NULL, kind TEXT NOT NULL,
  spec_kind TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, version, dst_name, kind));
CREATE INDEX IF NOT EXISTS dep_edge_dst ON dep_edge (ecosystem, dst_name);

-- Every integrity value ever observed for a version; >1 row = same-version change.
CREATE TABLE IF NOT EXISTS integrity_obs (
  ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
  integrity TEXT NOT NULL, observed_at TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, version, integrity));

CREATE TABLE IF NOT EXISTS risk_score (
  ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
  score INTEGER NOT NULL, tier TEXT NOT NULL, rules_version TEXT NOT NULL,
  reasons_json TEXT NOT NULL, computed_at TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, version, rules_version));

CREATE TABLE IF NOT EXISTS centrality (
  ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
  in_degree INTEGER NOT NULL, betweenness REAL NOT NULL,
  snapshot_id TEXT NOT NULL, computed_at TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, version, snapshot_id));

-- ---------------------------------------------------------------- feed (NT-006/007)
CREATE TABLE IF NOT EXISTS feed_checkpoint (
  feed TEXT PRIMARY KEY, seq TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS watchlist (
  ecosystem TEXT NOT NULL, name TEXT NOT NULL, reason TEXT NOT NULL, added_at TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name));
-- priority: feed/watchlist jobs (10) are served before SBOM-targeted jobs (0),
-- so untrusted scan input cannot starve crawling of watched packages.
CREATE TABLE IF NOT EXISTS fetch_job (
  ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  reason TEXT NOT NULL, seq TEXT, status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
  requested_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ecosystem, name));
CREATE TABLE IF NOT EXISTS sync_status (
  source TEXT PRIMARY KEY, last_success_at TEXT, last_attempt_at TEXT,
  last_error TEXT, detail_json TEXT NOT NULL DEFAULT '{}');

-- ---------------------------------------------------------------- intel (NT-011)
CREATE TABLE IF NOT EXISTS advisory (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, aliases_json TEXT NOT NULL,
  summary TEXT, kind TEXT NOT NULL,              -- 'vulnerability' | 'malicious_report'
  modified TEXT, withdrawn TEXT, fetched_at TEXT NOT NULL,
  affected_json TEXT NOT NULL, raw_sha256 TEXT NOT NULL, group_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS advisory_pkg (
  advisory_id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  PRIMARY KEY (advisory_id, ecosystem, name));
CREATE INDEX IF NOT EXISTS advisory_pkg_name ON advisory_pkg (ecosystem, name);
-- every id and alias of an advisory, for cross-source grouping
CREATE TABLE IF NOT EXISTS advisory_alias (
  alias TEXT NOT NULL, advisory_id TEXT NOT NULL, PRIMARY KEY (alias, advisory_id));

-- ---------------------------------------------------------------- application (NT-017+)
CREATE TABLE IF NOT EXISTS project (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL,
  alert_email TEXT);
CREATE TABLE IF NOT EXISTS api_key (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id),
  key_hash TEXT NOT NULL, role TEXT NOT NULL, label TEXT NOT NULL,
  created_at TEXT NOT NULL, created_by TEXT NOT NULL, revoked_at TEXT, last_used_at TEXT);
CREATE TABLE IF NOT EXISTS policy (
  project_id TEXT NOT NULL REFERENCES project(id), version INTEGER NOT NULL,
  config_json TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
  PRIMARY KEY (project_id, version));

CREATE TABLE IF NOT EXISTS scan (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id),
  commit_sha TEXT NOT NULL, branch TEXT NOT NULL, run_id TEXT,
  sbom_sha256 TEXT NOT NULL, received_at TEXT NOT NULL,
  root_ref TEXT, component_count INTEGER NOT NULL, quality TEXT NOT NULL,
  coverage_json TEXT NOT NULL,
  UNIQUE (project_id, commit_sha, sbom_sha256));
CREATE INDEX IF NOT EXISTS scan_project_branch ON scan (project_id, branch, received_at);
CREATE TABLE IF NOT EXISTS scan_component (
  scan_id TEXT NOT NULL REFERENCES scan(id), ref TEXT NOT NULL,
  purl TEXT, ecosystem TEXT, name TEXT NOT NULL, version TEXT,
  status TEXT NOT NULL,                          -- exact | unresolved | unsupported
  scope TEXT, is_direct INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (scan_id, ref));
CREATE INDEX IF NOT EXISTS scan_component_pkg ON scan_component (ecosystem, name, version);
CREATE TABLE IF NOT EXISTS scan_edge (
  scan_id TEXT NOT NULL REFERENCES scan(id), src_ref TEXT NOT NULL, dst_ref TEXT NOT NULL,
  PRIMARY KEY (scan_id, src_ref, dst_ref));
CREATE TABLE IF NOT EXISTS drift (
  scan_id TEXT PRIMARY KEY REFERENCES scan(id), project_id TEXT NOT NULL,
  base_scan_id TEXT, added_json TEXT NOT NULL, removed_json TEXT NOT NULL,
  changed_json TEXT NOT NULL, created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS incident (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, source TEXT NOT NULL,   -- manual | osv | crawler
  source_ref TEXT, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  affected_json TEXT NOT NULL,                   -- {"versions": [...], "ranges": [...]}
  risk_score INTEGER NOT NULL, evidence_status TEXT NOT NULL,
  evidence_version INTEGER NOT NULL DEFAULT 1, is_simulation INTEGER NOT NULL DEFAULT 0,
  detected_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  notes TEXT);

CREATE TABLE IF NOT EXISTS verdict (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, scan_id TEXT NOT NULL,
  commit_sha TEXT NOT NULL, policy_version INTEGER NOT NULL, mode TEXT NOT NULL,
  decision TEXT NOT NULL, assessment TEXT NOT NULL, body_json TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS verdict_scan ON verdict (project_id, scan_id);

CREATE TABLE IF NOT EXISTS alert (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, incident_id TEXT NOT NULL,
  dedup_key TEXT NOT NULL UNIQUE, tier TEXT NOT NULL, channel TEXT NOT NULL,
  delivery_status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT, last_error TEXT,
  triage_status TEXT NOT NULL, payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS alert_project ON alert (project_id, created_at);

CREATE TABLE IF NOT EXISTS approval (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, incident_id TEXT NOT NULL,
  scan_id TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL,
  requested_at TEXT NOT NULL, decided_by TEXT, decided_at TEXT, decision_note TEXT,
  UNIQUE (project_id, incident_id, scan_id));

CREATE TABLE IF NOT EXISTS override (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL, commit_sha TEXT NOT NULL,
  policy_version INTEGER NOT NULL, incident_id TEXT, scan_id TEXT, run_id TEXT,
  reason TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL,
  consumed_at TEXT, consumed_run_id TEXT, revoked_at TEXT);

CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
  project_id TEXT, action TEXT NOT NULL, target TEXT, detail_json TEXT NOT NULL,
  correlation_id TEXT);
CREATE INDEX IF NOT EXISTS audit_project ON audit (project_id, ts);

CREATE TABLE IF NOT EXISTS counter (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _migrate(con: sqlite3.Connection) -> None:
    """Additive migrations for databases created by earlier revisions."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(fetch_job)")}
    if "priority" not in cols:  # revision 1 -> 2
        con.execute("ALTER TABLE fetch_job ADD COLUMN priority INTEGER NOT NULL DEFAULT 0")
    con.execute("CREATE INDEX IF NOT EXISTS fetch_job_queue ON fetch_job (status, priority, requested_at)")
    # revision 2 -> 3: the real OSV npm export has ~229k records, most of them MAL-* reports that each
    # become an incident. Without these, every OSV record and every CI scan scanned whole tables.
    con.execute("CREATE INDEX IF NOT EXISTS incident_source_ref ON incident (source, source_ref)")
    con.execute("CREATE INDEX IF NOT EXISTS incident_name ON incident (ecosystem, name)")
    con.execute("CREATE INDEX IF NOT EXISTS advisory_group ON advisory (group_id)")
    con.execute("CREATE INDEX IF NOT EXISTS advisory_alias_advisory ON advisory_alias (advisory_id)")


class Database:
    """Thin wrapper: one short-lived connection per unit of work.

    SQLite in WAL mode handles the MVP's single API process + single worker.
    `transaction()` serialises writers inside this process to avoid
    'database is locked' under the FastAPI thread pool.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA busy_timeout=30000")
        return con

    def _init(self) -> None:
        con = self._connect()
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(_SCHEMA)
            _migrate(con)
            con.execute("INSERT INTO meta(key, value) VALUES ('schema_revision', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(SCHEMA_REVISION),))
        finally:
            con.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        con = self._connect()
        try:
            yield con
        finally:
            con.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._write_lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                yield con
                con.execute("COMMIT")
            except BaseException:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                raise
            finally:
                con.close()

    # -- small helpers used everywhere
    def audit(self, con: sqlite3.Connection, *, actor: str, action: str, project_id: str | None = None,
              target: str | None = None, detail: dict | None = None, correlation_id: str | None = None) -> None:
        con.execute(
            "INSERT INTO audit(ts, actor, project_id, action, target, detail_json, correlation_id) "
            "VALUES (?,?,?,?,?,?,?)",
            (utcnow(), actor, project_id, action, target, dumps(detail or {}), correlation_id),
        )

    def bump(self, con: sqlite3.Connection, name: str, by: int = 1) -> None:
        con.execute("INSERT INTO counter(name, value) VALUES (?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value", (name, by))

    def set_sync(self, source: str, *, ok: bool, error: str | None = None, detail: dict | None = None) -> None:
        now = utcnow()
        with self.transaction() as con:
            if ok:
                con.execute(
                    "INSERT INTO sync_status(source, last_success_at, last_attempt_at, last_error, detail_json) "
                    "VALUES (?,?,?,NULL,?) ON CONFLICT(source) DO UPDATE SET last_success_at=excluded.last_success_at,"
                    " last_attempt_at=excluded.last_attempt_at, last_error=NULL, detail_json=excluded.detail_json",
                    (source, now, now, dumps(detail or {})))
            else:
                con.execute(
                    "INSERT INTO sync_status(source, last_success_at, last_attempt_at, last_error, detail_json) "
                    "VALUES (?,NULL,?,?,'{}') ON CONFLICT(source) DO UPDATE SET "
                    "last_attempt_at=excluded.last_attempt_at, last_error=excluded.last_error",
                    (source, now, (error or "error")[:500]))


def monotonic_ms() -> int:
    return int(time.monotonic() * 1000)
