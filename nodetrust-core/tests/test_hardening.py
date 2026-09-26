"""Hardening after the 2026-09-26 self-review:
- untrusted SBOM input cannot flood the registry fetch queue (finding: one scan queued 3001 jobs,
  including a traversal-style name);
- API docs closed by default; failed-auth throttling per client IP; schema migration for old DBs."""

import sqlite3

from fastapi.testclient import TestClient

from nodetrust.api.app import create_app
from nodetrust.api.auth import AuthThrottle
from nodetrust.config import Settings
from nodetrust.exposure.scans import FetchBudget, store_scan
from nodetrust.registry.feed import PRIORITY_FEED, enqueue_fetch
from nodetrust.registry.fetch import Fetcher
from nodetrust.registry.transport import FakeTransport
from nodetrust.sbom.cyclonedx import parse_cyclonedx
from nodetrust.storage import Database
from sbomkit import make_sbom

OP = "operator-token-for-tests-0123456789"


def junk_sbom(n, extra=()):
    comps = [{"type": "library", "bom-ref": f"r{i}", "name": "x", "version": "1.0.0",
              "purl": f"pkg:npm/junk-{i}@1.0.0"} for i in range(n)] + list(extra)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "root", "name": "a"}},
            "components": comps, "dependencies": [{"ref": "root", "dependsOn": [c["bom-ref"] for c in comps]}]}


def project(db, pid="p"):
    with db.transaction() as con:
        con.execute("INSERT INTO project(id, name, created_at) VALUES (?, ?, 'now')", (pid, pid))


def jobs(db):
    with db.read() as con:
        return {r["name"]: dict(r) for r in con.execute("SELECT * FROM fetch_job")}


def test_invalid_npm_names_never_reach_the_queue(db):
    project(db)
    evil = {"type": "library", "bom-ref": "t", "name": "x", "version": "1.0.0", "purl": "pkg:npm/..%2F..%2Fadmin@1.0.0"}
    sb = parse_cyclonedx(junk_sbom(1, [evil]))
    assert sb.components["t"].status == "out_of_scope" and sb.components["t"].ecosystem is None
    assert any("not a valid npm package name" in w for w in sb.warnings)
    with db.transaction() as con:
        store_scan(con, project_id="p", sbom=sb, commit_sha="a" * 40, branch="main", run_id=None)
    assert set(jobs(db)) == {"junk-0"}


def test_per_scan_budget_and_global_ceiling(db):
    project(db)
    with db.transaction() as con:
        sid, _ = store_scan(con, project_id="p", sbom=parse_cyclonedx(junk_sbom(3000)), commit_sha="a" * 40,
                            branch="main", run_id=None, budget=FetchBudget(per_scan=200, max_pending=250))
        cov = con.execute("SELECT coverage_json FROM scan WHERE id=?", (sid,)).fetchone()[0]
    assert len(jobs(db)) == 200 and '"not_queued":2800' in cov.replace(" ", "")
    with db.transaction() as con:  # second scan only fills up to the global ceiling
        store_scan(con, project_id="p", sbom=parse_cyclonedx(junk_sbom(3000)), commit_sha="b" * 40,
                   branch="main", run_id=None, budget=FetchBudget(per_scan=200, max_pending=250))
    assert len(jobs(db)) == 250


def test_cooldown_prevents_refetch_on_every_scan(db):
    with db.transaction() as con:
        assert enqueue_fetch(con, "gone", "sbom:p", priority=0, cooldown_hours=24)
        con.execute("UPDATE fetch_job SET status='done'")
        assert not enqueue_fetch(con, "gone", "sbom:p", priority=0, cooldown_hours=24)  # fetched recently
        con.execute("UPDATE fetch_job SET updated_at='2020-01-01T00:00:00Z'")
        assert enqueue_fetch(con, "gone", "sbom:p", priority=0, cooldown_hours=24)  # stale -> re-queued
    assert jobs(db)["gone"]["status"] == "pending"


def test_feed_jobs_are_served_before_sbom_jobs(db):
    with db.transaction() as con:
        for i in range(5):
            enqueue_fetch(con, f"sbom-{i}", "sbom:p", priority=0)
        enqueue_fetch(con, "watched", "feed", priority=PRIORITY_FEED)
        enqueue_fetch(con, "sbom-0", "feed", priority=PRIORITY_FEED)  # promoted, never demoted
        enqueue_fetch(con, "sbom-0", "sbom:p", priority=0)
    t = FakeTransport()
    Fetcher(db, t, "https://reg.test", sleep=lambda s: None).process_pending(limit=2)
    assert sorted(u for _, u in t.calls) == ["https://reg.test/sbom-0", "https://reg.test/watched"]
    assert jobs(db)["sbom-0"]["reason"] == "feed"


def test_old_database_is_migrated(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript("""CREATE TABLE fetch_job (ecosystem TEXT NOT NULL, name TEXT NOT NULL, reason TEXT NOT NULL,
        seq TEXT, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
        requested_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (ecosystem, name));
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO meta VALUES ('schema_revision', '1');
        INSERT INTO fetch_job VALUES ('npm','a','feed',NULL,'pending',0,NULL,'t','t');""")
    con.commit()
    con.close()
    db = Database(path)
    assert jobs(db)["a"]["priority"] == 0
    with db.read() as c:
        assert c.execute("SELECT value FROM meta WHERE key='schema_revision'").fetchone()[0] == "2"


def test_api_docs_closed_by_default(tmp_path):
    closed = TestClient(create_app(Settings(db_path=tmp_path / "a.db")))
    assert closed.get("/docs").status_code == 404 and closed.get("/openapi.json").status_code == 404
    opened = TestClient(create_app(Settings(db_path=tmp_path / "b.db", expose_api_docs=True)))
    assert opened.get("/openapi.json").status_code == 200


def test_failed_auth_is_throttled_per_ip_but_success_is_not_counted(tmp_path):
    client = TestClient(create_app(Settings(db_path=tmp_path / "t.db", admin_token=OP, auth_max_failures=3,
                                            auth_failure_window_s=60)))
    for _ in range(5):
        assert client.get("/v1/projects", headers={"Authorization": f"Bearer {OP}"}).status_code == 200
    for _ in range(3):
        assert client.get("/v1/projects", headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = client.get("/v1/projects", headers={"Authorization": f"Bearer {OP}"})
    assert r.status_code == 429 and r.json()["error"]["code"] == "rate_limited" and int(r.headers["retry-after"]) >= 1


def test_throttle_window_expires():
    now = [0.0]
    th = AuthThrottle(2, 10, clock=lambda: now[0])
    th.record_failure("1.2.3.4")
    th.record_failure("1.2.3.4")
    assert th.retry_after("1.2.3.4") and th.retry_after("5.6.7.8") is None
    now[0] = 11
    assert th.retry_after("1.2.3.4") is None


def test_scan_api_reports_queue_limits(tmp_path):
    s = Settings(db_path=tmp_path / "q.db", admin_token=OP, snapshot_mode=True, fetch_budget_per_scan=5)
    client = TestClient(create_app(s))
    body = client.post("/v1/projects", json={"name": "q"}, headers={"Authorization": f"Bearer {OP}"}).json()
    r = client.post(f"/v1/projects/{body['project']['id']}/scans",
                    headers={"Authorization": f"Bearer {body['admin_key']}"},
                    json={"commit": "a" * 40, "branch": "main", "sbom": make_sbom({"root": [f"p{i}@1.0.0" for i in range(12)]})})
    cov = r.json()["data_quality"]["coverage"]
    assert (cov["not_in_graph"], cov["queued_for_fetch"], cov["not_queued"]) == (12, 5, 7)
