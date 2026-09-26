"""NT-042 backup/restore/retention, NT-026 dashboard serving, demo seed, health."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nodetrust.api.app import create_app
from nodetrust.config import Settings
from nodetrust.demo import seed_demo
from nodetrust.ops import backup, purge, restore, verify_backup
from nodetrust.storage import Database

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "demo"


def test_backup_restore_roundtrip_with_checksum(tmp_path):
    db = Database(tmp_path / "live.db")
    with db.transaction() as con:
        con.execute("INSERT INTO project(id, name, created_at) VALUES ('prj_1', 'p', 'now')")
    info = backup(tmp_path / "live.db", tmp_path / "bk" / "b1.db")
    assert verify_backup(tmp_path / "bk" / "b1.db")["integrity"] == "ok"
    with pytest.raises(FileExistsError):
        backup(tmp_path / "live.db", tmp_path / "bk" / "b1.db")
    with db.transaction() as con:
        con.execute("DELETE FROM project")
    res = restore(tmp_path / "bk" / "b1.db", tmp_path / "live.db")
    assert res["sha256"] == info["sha256"] and res["previous_kept_at"]
    with Database(tmp_path / "live.db").read() as con:
        assert con.execute("SELECT COUNT(*) FROM project").fetchone()[0] == 1


def test_restore_rejects_tampered_backup(tmp_path):
    Database(tmp_path / "live.db")
    backup(tmp_path / "live.db", tmp_path / "b.db")
    with open(tmp_path / "b.db", "ab") as f:
        f.write(b"tamper")
    with pytest.raises(ValueError, match="checksum"):
        restore(tmp_path / "b.db", tmp_path / "other.db")


def test_purge_only_touches_operational_data(tmp_path):
    db = Database(tmp_path / "p.db")
    with db.transaction() as con:
        con.execute("INSERT INTO fetch_job(ecosystem, name, reason, status, requested_at, updated_at) "
                    "VALUES ('npm','old','x','done','2020-01-01T00:00:00Z','2020-01-01T00:00:00Z')")
        con.execute("INSERT INTO fetch_job(ecosystem, name, reason, status, requested_at, updated_at) "
                    "VALUES ('npm','pending','x','pending','2020-01-01T00:00:00Z','2020-01-01T00:00:00Z')")
        db.audit(con, actor="t", action="x")
        res = purge(con, days=30)
        assert res["fetch_jobs_deleted"] == 1
        assert con.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 1
        assert con.execute("SELECT name FROM fetch_job").fetchone()[0] == "pending"


def test_dashboard_is_served_with_strict_csp(tmp_path):
    client = TestClient(create_app(Settings(db_path=tmp_path / "d.db")))
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307) and r.headers["location"] == "/dashboard/"
    page = client.get("/dashboard/")
    assert page.status_code == 200 and "app.js" in page.text
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert client.get("/dashboard/app.js").status_code == 200
    # no inline script or style in the page (CSP would block it anyway)
    assert "<script>" not in page.text and "style=" not in page.text


def test_demo_seed_produces_expected_decisions(tmp_path):
    db = Database(tmp_path / "demo.db")
    out = seed_demo(db, FIXTURES)
    assert out["scans"]["demo-exposed/exposed-old"]["decision"] == "pass"
    new = out["scans"]["demo-exposed/exposed-new"]
    # D05 option 1: the demo project is small (T < 200), so its radius is small and the pre-authorised gate applies
    assert new["decision"] == "gate" and "simulation" in new["labels"]
    assert out["scans"]["demo-clean/clean"]["decision"] == "pass"
    with db.read() as con:
        crawler = con.execute("SELECT risk_score, evidence_status FROM incident WHERE source='crawler'").fetchall()
    assert [(r[0], r[1]) for r in crawler] == [(90, "unverified")]
    with pytest.raises(SystemExit):
        seed_demo(db, FIXTURES)  # refuses to double-seed


def test_demo_dashboard_endpoints_work_with_demo_keys(tmp_path):
    s = Settings(db_path=tmp_path / "demo.db", snapshot_mode=True)
    out = seed_demo(Database(s.db_path), FIXTURES)
    client = TestClient(create_app(s))
    p = out["projects"]["demo-exposed"]
    h = {"Authorization": f"Bearer {p['admin_key']}"}
    scans = client.get(f"/v1/projects/{p['id']}/scans", headers=h).json()["scans"]
    sid = scans[0]["id"]
    g = client.get(f"/v1/projects/{p['id']}/scans/{sid}/graph", headers=h).json()
    assert any(n.get("root") for n in g["nodes"]) and g["edges"]
    blast = client.get("/v1/graph/blast?name=ntdemo-utils&version=2.1.1", headers=h).json()
    assert blast["count"] >= 3 and blast["forecast"]["kind"] == "heuristic_simulation"
    assert blast["forecast"]["validated"] is False
    lkg = client.get(f"/v1/projects/{p['id']}/lkg?name=ntdemo-utils&bad=2.1.1", headers=h).json()
    assert lkg["available"] and lkg["version"] == "2.1.0"
    rep = client.get(f"/v1/projects/{out['projects']['demo-clean']['id']}/scans/"
                     f"{out['scans']['demo-clean/clean']['scan_id']}/report",
                     headers={"Authorization": f"Bearer {out['projects']['demo-clean']['admin_key']}"}).json()
    assert rep["vulnerabilities"][0]["ids"] == ["NTDEMO-VULN-0001"]
    assert rep["vulnerabilities"][0]["is_evidence_of_compromise"] is False


def _as_installed(monkeypatch, root: Path) -> None:
    # pip install . puts cli.py in site-packages, far from the repo's fixtures/ directory.
    import nodetrust.cli

    monkeypatch.setattr(nodetrust.cli, "__file__", str(root / "site-packages" / "nodetrust" / "cli.py"))
    monkeypatch.setenv("NODETRUST_DB_PATH", str(root / "demo.db"))


def test_installed_demo_cli_uses_fixtures_in_working_dir(tmp_path, monkeypatch):
    import shutil

    from nodetrust.cli import main

    _as_installed(monkeypatch, tmp_path)
    shutil.copytree(FIXTURES, tmp_path / "app" / "fixtures" / "demo")
    monkeypatch.chdir(tmp_path / "app")  # the Docker image's WORKDIR holds fixtures/
    assert main(["demo"]) == 0


def test_installed_demo_cli_without_fixtures_fails_clearly(tmp_path, monkeypatch, capsys):
    from nodetrust.cli import main

    _as_installed(monkeypatch, tmp_path)
    monkeypatch.chdir(tmp_path)
    assert main(["demo"]) == 2
    assert "--fixtures" in capsys.readouterr().err
