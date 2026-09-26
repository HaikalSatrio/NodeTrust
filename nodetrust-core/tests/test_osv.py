"""NT-011: OSV import, matching, dedup, withdrawn handling, malicious-report incidents."""

import json
import zipfile

import pytest

from nodetrust.incidents import affects, list_incidents
from nodetrust.intel.osv import OsvClient, advisories_for, import_records, iter_zip
from nodetrust.registry.transport import FakeTransport, Response, TransportError


def rec(rid, name, events=None, versions=None, aliases=(), withdrawn=None, eco="npm", modified="2026-09-01T00:00:00Z"):
    a = {"package": {"ecosystem": eco, "name": name}}
    if events:
        a["ranges"] = [{"type": "SEMVER", "events": events}]
    if versions:
        a["versions"] = versions
    d = {"id": rid, "modified": modified, "aliases": list(aliases), "summary": f"{rid} summary", "affected": [a]}
    if withdrawn:
        d["withdrawn"] = withdrawn
    return d


@pytest.mark.parametrize("version,hit", [("0.9.0", True), ("1.2.3", True), ("1.2.4", False), ("2.0.0", True),
                                         ("2.0.1", False), ("3.1.0", True), ("3.2.0", False)])
def test_range_events(version, hit):
    affected = {"ranges": [{"type": "SEMVER", "events": [
        {"introduced": "0"}, {"fixed": "1.2.4"}, {"introduced": "2.0.0"}, {"fixed": "2.0.1"},
        {"introduced": "3.0.0"}, {"last_affected": "3.1.0"}]}]}
    assert affects(affected, version) is hit


def test_import_matches_groups_aliases_and_ignores_withdrawn(db):
    rep = import_records(db, [
        rec("GHSA-aaaa", "lib", events=[{"introduced": "0"}, {"fixed": "1.2.4"}], aliases=["CVE-2026-1"]),
        rec("CVE-2026-1", "lib", events=[{"introduced": "1.0.0"}, {"fixed": "1.2.4"}], aliases=["GHSA-aaaa"]),
        rec("GHSA-old", "lib", versions=["1.0.0"], withdrawn="2026-09-02T00:00:00Z"),
        rec("PYSEC-1", "lib", versions=["1.0.0"], eco="PyPI"),
        {"id": "bad"},
    ], source="fixture")
    assert (rep.inserted, rep.skipped_other_ecosystem, len(rep.invalid)) == (3, 1, 1)
    with db.read() as con:
        hits = advisories_for(con, "lib", "1.0.0")
        assert len(hits) == 1  # one group, withdrawn excluded
        g = hits[0]
        assert g["ids"] == ["CVE-2026-1", "GHSA-aaaa"] and g["kind"] == "vulnerability"
        assert g["is_evidence_of_compromise"] is False and g["sources"] == ["fixture"]
        assert advisories_for(con, "lib", "1.2.4") == []
        row = con.execute("SELECT fetched_at, source FROM advisory WHERE id='GHSA-aaaa'").fetchone()
        assert row["fetched_at"] and row["source"] == "fixture"
        assert list_incidents(con) == []  # vulnerabilities are not incidents


def test_reimport_is_deduplicated_and_updates_on_change(db):
    r = rec("GHSA-x", "lib", versions=["1.0.0"])
    import_records(db, [r], source="s")
    assert import_records(db, [r], source="s").unchanged == 1
    r2 = dict(r, modified="2026-09-05T00:00:00Z", summary="changed")
    assert import_records(db, [r2], source="s").updated == 1


def test_malicious_report_creates_unverified_incident_once(db):
    mal = rec("MAL-2026-9", "evil-pkg", versions=["1.0.0", "1.0.1"])
    assert import_records(db, [mal], source="s").incidents_created == 1
    assert import_records(db, [dict(mal, modified="2026-09-09T00:00:00Z")], source="s").incidents_created == 0
    with db.read() as con:
        (inc,) = list_incidents(con)
    assert inc["source"] == "osv" and inc["evidence_status"] == "unverified" and inc["tier"] == "INVESTIGATE"


def test_zip_import(tmp_path, db):
    z = tmp_path / "all.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("GHSA-z.json", json.dumps(rec("GHSA-z", "lib", versions=["2.0.0"])))
        zf.writestr("broken.json", "{")
    rep = import_records(db, iter_zip(z), source="osv-zip")
    assert rep.inserted == 1 and len(rep.invalid) == 1


def test_api_client_records_failures(db):
    t = FakeTransport({"https://osv.test/v1/query": [Response(500, b"")]})
    with pytest.raises(TransportError):
        OsvClient(db, t, "https://osv.test/v1", sleep=lambda s: None).query_package("lib")
    with db.read() as con:
        assert con.execute("SELECT last_error FROM sync_status WHERE source='intel:osv'").fetchone()[0]
    t.routes["https://osv.test/v1/query"] = [Response(200, json.dumps({"vulns": [rec("GHSA-q", "lib", versions=["1.0.0"])]}).encode())]
    assert OsvClient(db, t, "https://osv.test/v1", sleep=lambda s: None).query_package("lib").inserted == 1


def test_api_client_follows_next_page_token(db):
    url = "https://osv.test/v1/query"
    page1 = {"vulns": [rec("GHSA-p1", "lib", versions=["1.0.0"])], "next_page_token": "tok-2"}
    page2 = {"vulns": [rec("GHSA-p2", "lib", versions=["1.0.1"])]}
    t = FakeTransport({url: [Response(200, json.dumps(page1).encode()), Response(200, json.dumps(page2).encode())]})
    assert OsvClient(db, t, "https://osv.test/v1", sleep=lambda s: None).query_package("lib").inserted == 2
    assert [u for _, u in t.calls] == [url, url]


def test_api_client_refuses_endless_pagination(db):
    endless = {"vulns": [], "next_page_token": "again"}
    t = FakeTransport({"https://osv.test/v1/query": [Response(200, json.dumps(endless).encode())]})
    with pytest.raises(TransportError, match="exceeds 3 pages"):
        OsvClient(db, t, "https://osv.test/v1", sleep=lambda s: None).query_package("lib", max_pages=3)
    with db.read() as con:
        assert con.execute("SELECT COUNT(*) FROM advisory").fetchone()[0] == 0
