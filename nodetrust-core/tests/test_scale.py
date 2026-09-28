"""Indexes and scoped lookups found necessary by the real OSV npm import (~229k records)."""

from pathlib import Path

from nodetrust.incidents import create_incident, list_incidents
from nodetrust.storage import SCHEMA_REVISION, Database

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "demo"


def plan(con, sql, args=()):
    return " | ".join(r["detail"] for r in con.execute("EXPLAIN QUERY PLAN " + sql, args))


def test_hot_lookups_use_indexes(db):
    with db.read() as con:
        assert "incident_source_ref" in plan(con, "SELECT 1 FROM incident WHERE source='osv' AND source_ref=?", ("x",))
        assert "incident_source_ref" in plan(con, "SELECT id FROM incident WHERE source='crawler' AND source_ref=?", ("x",))
        assert "incident_name" in plan(con, "SELECT * FROM incident WHERE ecosystem='npm' AND name IN (?, ?)", ("a", "b"))
        assert "advisory_alias_advisory" in plan(con, "DELETE FROM advisory_alias WHERE advisory_id=?", ("x",))
        assert "advisory_group" in plan(con, "UPDATE advisory SET group_id=? WHERE group_id=?", ("a", "b"))


def _incident(con, name, n=0):
    return create_incident(con, title=f"t {name} {n}", name=name, affected={"versions": ["1.0.0"]}, risk_score=50)


def test_list_incidents_by_names_only_returns_those_packages(db):
    with db.transaction() as con:
        for i in range(1200):
            _incident(con, f"noise-{i}")
        _incident(con, "wanted-a")
        _incident(con, "wanted-b")
    with db.read() as con:
        assert {i["name"] for i in list_incidents(con, names={"wanted-a", "wanted-b", "absent"})} == {"wanted-a", "wanted-b"}
        # more names than SQLite's parameter limit allows in one IN (...)
        many = [f"noise-{i}" for i in range(1000)] + ["wanted-a"]
        assert len(list_incidents(con, names=many)) == 1001
        assert list_incidents(con, names=[]) == []
        assert len(list_incidents(con, limit=5)) == 5


def test_scan_matching_asks_only_for_the_scan_packages(tmp_path, monkeypatch):
    import nodetrust.exposure.matching as matching
    from nodetrust.demo import seed_demo

    seen = []
    real = matching.list_incidents

    def spy(con, **kw):
        seen.append(kw)
        return real(con, **kw)

    monkeypatch.setattr(matching, "list_incidents", spy)
    seed_demo(Database(tmp_path / "d.db"), FIXTURES)
    assert seen and all(kw.get("names") is not None for kw in seen)


def test_revision_2_database_gets_the_new_indexes(tmp_path):
    path = tmp_path / "old.db"
    db = Database(path)
    with db.transaction() as con:
        for idx in ("incident_source_ref", "incident_name", "advisory_group", "advisory_alias_advisory"):
            con.execute(f"DROP INDEX {idx}")
        con.execute("UPDATE meta SET value='2' WHERE key='schema_revision'")
    db = Database(path)  # reopen, as a restarted server would
    with db.read() as con:
        names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        rev = con.execute("SELECT value FROM meta WHERE key='schema_revision'").fetchone()[0]
    assert {"incident_source_ref", "incident_name", "advisory_group", "advisory_alias_advisory"} <= names
    assert rev == str(SCHEMA_REVISION) == "3"
