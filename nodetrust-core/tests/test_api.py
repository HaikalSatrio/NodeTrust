"""API integration: NT-017 auth/isolation, NT-018 intake, NT-019 report, NT-020 drift,
NT-022 policy/approval/override, NT-023 alerts/triage, NT-025 LKG, NT-042 health/audit.
Scenario numbers refer to the NT-001 acceptance list."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from nodetrust.alerts import OutboxSender, dispatch_pending
from nodetrust.api.app import create_app
from nodetrust.config import Settings
from sbomkit import make_sbom

OP = "operator-token-for-tests-0123456789"
C1, C2, C3 = "a" * 40, "b" * 40, "c" * 40


@pytest.fixture
def env(tmp_path):
    s = Settings(db_path=tmp_path / "api.db", admin_token=OP, snapshot_mode=True, alert_outbox_dir=tmp_path / "out")
    app = create_app(s)
    return TestClient(app), app


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def new_project(client, name="proj", email="owner@example.test"):
    r = client.post("/v1/projects", json={"name": name, "alert_email": email}, headers=H(OP))
    assert r.status_code == 201, r.text
    body = r.json()
    pid, admin = body["project"]["id"], body["admin_key"]
    ci = client.post(f"/v1/projects/{pid}/keys", json={"role": "ci", "label": "gha"}, headers=H(admin)).json()["key"]
    return pid, admin, ci


def incident(client, package, versions, score, sim=False, **kw):
    r = client.post("/v1/incidents", json={"title": f"test incident {package}", "package": package,
                                           "affected": {"versions": versions}, "risk_score": score,
                                           "is_simulation": sim, **kw}, headers=H(OP))
    assert r.status_code == 201, r.text
    return r.json()


def verify(client, iid, score=None):
    body = {"evidence_status": "verified"}
    if score is not None:
        body["risk_score"] = score
    r = client.patch(f"/v1/incidents/{iid}", json=body, headers=H(OP))
    assert r.status_code == 200
    return r.json()


def scan(client, pid, key, tree, commit=C1, run_id=None, branch="main", **kw):
    return client.post(f"/v1/projects/{pid}/scans", headers=H(key),
                       json={"commit": commit, "branch": branch, "run_id": run_id, "sbom": make_sbom(tree, **kw)})


def set_policy(client, pid, admin, **kw):
    r = client.put(f"/v1/projects/{pid}/policy", json=kw, headers=H(admin))
    assert r.status_code == 200, r.text
    return r.json()["version"]


TREE = {"root": ["web@1.0.0", "util@2.0.0"], "web@1.0.0": ["util@2.0.0", "evil@1.0.1"]}
# Same exposure inside a realistically sized project: 2 of 23 versions (8.7%) -> small radius under D05.
BIG = {**TREE, "root": TREE["root"] + [f"filler{i}@1.0.0" for i in range(20)]}


# ------------------------------------------------------------------ NT-017

def test_health_and_meta(env):
    client, _ = env
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json()["status"] == "ready"
    assert client.get("/v1/meta").json()["network_enabled"] is False


def test_auth_required_and_operator_separated(env):
    client, _ = env
    assert client.post("/v1/projects", json={"name": "x"}).status_code == 401
    assert client.post("/v1/projects", json={"name": "x"}, headers=H("wrong")).status_code == 401
    pid, admin, ci = new_project(client)
    assert client.post("/v1/projects", json={"name": "x"}, headers=H(admin)).status_code == 403
    # operator has no project-level powers
    assert client.get(f"/v1/projects/{pid}", headers=H(OP)).status_code == 404


def test_project_isolation_and_roles(env):
    client, _ = env
    a, a_admin, a_ci = new_project(client, "A")
    b, b_admin, b_ci = new_project(client, "B")
    assert scan(client, a, a_ci, TREE).status_code == 200
    sid = client.get(f"/v1/projects/{a}/scans", headers=H(a_ci)).json()["scans"][0]["id"]
    # B cannot see A (404, existence not revealed) on every read path
    for path in [f"/v1/projects/{a}", f"/v1/projects/{a}/scans", f"/v1/projects/{a}/scans/{sid}/report",
                 f"/v1/projects/{a}/alerts", f"/v1/projects/{a}/policy"]:
        assert client.get(path, headers=H(b_admin)).status_code == 404, path
    # B cannot fetch A's scan through its own project path either
    assert client.get(f"/v1/projects/{b}/scans/{sid}", headers=H(b_admin)).status_code == 404
    # ci role cannot administer
    assert client.put(f"/v1/projects/{a}/policy", json={}, headers=H(a_ci)).status_code == 403
    assert client.post(f"/v1/projects/{a}/keys", json={"role": "admin", "label": "x"}, headers=H(a_ci)).status_code == 403
    assert client.get(f"/v1/projects/{a}/audit", headers=H(a_ci)).status_code == 403


def test_key_revocation(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    keys = client.get(f"/v1/projects/{pid}/keys", headers=H(admin)).json()["keys"]
    ci_id = [k for k in keys if k["role"] == "ci"][0]["id"]
    assert all("key_hash" not in k for k in keys)
    assert client.delete(f"/v1/projects/{pid}/keys/{ci_id}", headers=H(admin)).status_code == 200
    assert client.get(f"/v1/projects/{pid}", headers=H(ci)).status_code == 401


# ------------------------------------------------------------------ NT-018 / 019 / 020

def test_scan_validation_errors(env):
    client, app = env
    pid, admin, ci = new_project(client)
    bad = client.post(f"/v1/projects/{pid}/scans", headers=H(ci),
                      json={"commit": C1, "branch": "main", "sbom": {"bomFormat": "SPDX"}})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_sbom"
    badc = client.post(f"/v1/projects/{pid}/scans", headers=H(ci),
                       json={"commit": "not-a-sha", "branch": "main", "sbom": make_sbom(TREE)})
    assert badc.status_code == 422 and badc.json()["error"]["code"] == "invalid_request"
    app.state.settings.max_sbom_bytes = 1000
    big = scan(client, pid, ci, {"root": [f"pkg{i}@1.0.0" for i in range(200)]})
    assert big.status_code == 413 and big.json()["error"]["code"] == "payload_too_large"


def test_scan_is_idempotent_and_drift_tracks_pushes(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    v1 = scan(client, pid, ci, TREE, commit=C1).json()
    again = scan(client, pid, ci, TREE, commit=C1).json()
    assert again["scan_reused"] and again["scan"]["scan_id"] == v1["scan"]["scan_id"]
    assert v1["drift"]["first_scan"]
    tree2 = {"root": ["web@1.1.0", "util@2.0.0", "new@0.1.0"], "web@1.1.0": ["util@2.0.0"]}
    v2 = scan(client, pid, ci, tree2, commit=C2).json()
    d = client.get(f"/v1/projects/{pid}/scans/{v2['scan']['scan_id']}/drift", headers=H(ci)).json()
    assert d["baseline"]["commit_sha"] == C1 and d["scan"]["commit_sha"] == C2
    assert [x["name"] for x in d["added"]] == ["new"]
    assert [x["name"] for x in d["removed"]] == ["evil"]
    assert d["changed"] == [{"name": "web", "from": ["1.0.0"], "to": ["1.1.0"]}]
    assert len(client.get(f"/v1/projects/{pid}/scans", headers=H(ci)).json()["scans"]) == 2


def test_baseline_report_counts_and_unknowns(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    v = scan(client, pid, ci, TREE).json()
    rep = client.get(f"/v1/projects/{pid}/scans/{v['scan']['scan_id']}/report", headers=H(ci)).json()
    assert rep["counts"]["direct"] == 2 and rep["counts"]["transitive"] == 1
    assert rep["coverage"]["in_graph"] == 0 and rep["coverage"]["not_assessed"] == 3  # empty graph: unknown, not safe
    assert {c["package"] for c in rep["choke_points"]} == {"web@1.0.0"}  # only path to evil
    with client.app.state.db.read() as con:  # unknown packages queued for targeted fetch
        assert {r[0] for r in con.execute("SELECT name FROM fetch_job")} == {"web", "util", "evil"}


# ------------------------------------------------------------------ exposure, policy, alerts

def test_s8_only_exposed_project_gets_alert(env, tmp_path):
    client, app = env
    a, a_admin, a_ci = new_project(client, "A", "a@example.test")
    b, b_admin, b_ci = new_project(client, "B", "b@example.test")
    incident(client, "evil", ["1.0.1"], 80)
    va = scan(client, a, a_ci, TREE).json()
    vb = scan(client, b, b_ci, {"root": ["util@2.0.0"]}).json()
    assert va["decision"] == "warn" and va["findings"][0]["exposure"] == "exposed"
    assert va["findings"][0]["paths"] == [["(project root)", "web@1.0.0", "evil@1.0.1"]]
    assert vb["findings"] == [] and vb["decision"] == "pass"
    assert len(client.get(f"/v1/projects/{a}/alerts", headers=H(a_ci)).json()["alerts"]) == 1
    assert client.get(f"/v1/projects/{b}/alerts", headers=H(b_ci)).json()["alerts"] == []
    # delivery to the offline outbox; alert body never mentions the other project
    rep = dispatch_pending(app.state.db, OutboxSender(tmp_path / "out"))
    assert rep["sent"] == 1
    (eml,) = list((tmp_path / "out").glob("*.eml"))
    text = eml.read_text()
    assert "evil" in text and "B" not in text.split("Subject:")[1].splitlines()[0]
    assert "a@example.test" in text


def test_s2_watch_records_without_email(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    incident(client, "evil", ["1.0.1"], 55)
    v = scan(client, pid, ci, TREE).json()
    assert v["decision"] == "warn" and v["findings"][0]["tier"] == "WATCH" and v["alerts_raised"] == []
    set_policy(client, pid, admin, watch_email=True)
    v2 = scan(client, pid, ci, TREE).json()
    assert len(v2["alerts_raised"]) == 1


def test_resubmission_does_not_duplicate_alerts_but_evidence_change_does(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    inc = incident(client, "evil", ["1.0.1"], 80)
    assert len(scan(client, pid, ci, TREE).json()["alerts_raised"]) == 1
    assert scan(client, pid, ci, TREE).json()["alerts_raised"] == []
    verify(client, inc["id"], score=95)
    assert len(scan(client, pid, ci, TREE).json()["alerts_raised"]) == 1


def test_s4_gate_requires_preauthorisation(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    verify(client, incident(client, "evil", ["1.0.1"], 95)["id"])
    assert scan(client, pid, ci, BIG).json()["decision"] == "warn"  # monitor default
    set_policy(client, pid, admin, mode="enforce")
    assert scan(client, pid, ci, BIG).json()["decision"] == "warn"  # not pre-authorised
    set_policy(client, pid, admin, mode="enforce", preauthorize_gate_verified_critical=True)
    v = scan(client, pid, ci, BIG).json()
    assert v["decision"] == "gate" and v["exit_code"] == 1 and v["policy_version"] == 3
    assert v["findings"][0]["radius"]["affected_versions"] == 2 and v["findings"][0]["radius"]["total_versions"] == 23
    # D05 option 1: in a 3-package project 2/3 is still a small radius (T < 200: only A >= 100 counts)
    small = scan(client, pid, ci, TREE, commit=C2).json()
    assert small["decision"] == "gate" and small["findings"][0]["radius"]["total_versions"] == 3


def test_large_radius_hold_and_human_approval(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    verify(client, incident(client, "evil", ["1.0.1"], 95)["id"])
    set_policy(client, pid, admin, mode="enforce", preauthorize_gate_verified_critical=True,
               preauthorize_hold_large_radius=True, radius_abs_threshold=2)
    v = scan(client, pid, ci, TREE).json()
    assert v["decision"] == "pending_approval" and v["exit_code"] == 1
    (apr,) = v["approvals_pending"]
    # CI key cannot approve (approval cannot be forged by the pipeline)
    assert client.post(f"/v1/projects/{pid}/approvals/{apr}", json={"decision": "allow", "note": "looks fine"},
                       headers=H(ci)).status_code == 403
    r = client.post(f"/v1/projects/{pid}/approvals/{apr}", json={"decision": "allow", "note": "checked the tarball"},
                    headers=H(admin))
    assert r.status_code == 200
    assert client.post(f"/v1/projects/{pid}/approvals/{apr}", json={"decision": "block", "note": "changed mind"},
                       headers=H(admin)).status_code == 409
    assert scan(client, pid, ci, TREE).json()["decision"] == "warn"


def test_s9_override_one_run_expiry_and_evidence_binding(env):
    client, app = env
    pid, admin, ci = new_project(client)
    inc = verify(client, incident(client, "evil", ["1.0.1"], 95)["id"])
    set_policy(client, pid, admin, mode="enforce", preauthorize_gate_verified_critical=True)
    v = scan(client, pid, ci, BIG, run_id="run-1").json()
    assert v["decision"] == "gate"
    sid = v["scan"]["scan_id"]
    assert client.post(f"/v1/projects/{pid}/overrides", json={"scan_id": sid, "reason": "short", "hours": 1},
                       headers=H(admin)).status_code == 422
    assert client.post(f"/v1/projects/{pid}/overrides", json={"scan_id": sid, "reason": "x" * 20, "hours": 30},
                       headers=H(admin)).status_code == 422
    assert client.post(f"/v1/projects/{pid}/overrides", json={"scan_id": sid, "reason": "hotfix, reviewed by sec",
                                                              "hours": 2}, headers=H(ci)).status_code == 403
    o = client.post(f"/v1/projects/{pid}/overrides", json={"scan_id": sid, "reason": "hotfix, reviewed by sec",
                                                           "hours": 2}, headers=H(admin)).json()
    v1 = scan(client, pid, ci, BIG, run_id="run-2").json()
    assert v1["decision"] == "warn" and v1["override"]["id"] == o["id"]
    assert v1["findings"], "findings must be kept when overridden"
    assert scan(client, pid, ci, BIG, run_id="run-2").json()["decision"] == "warn"  # same run may retry
    v2 = scan(client, pid, ci, BIG, run_id="run-3").json()
    assert v2["decision"] == "gate" and any("already used" in r["message"] for r in v2["reasons"])
    # expired override
    o2 = client.post(f"/v1/projects/{pid}/overrides", json={"scan_id": sid, "reason": "another reviewed exception",
                                                            "hours": 1}, headers=H(admin)).json()
    with app.state.db.transaction() as con:
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        con.execute("UPDATE override SET expires_at=? WHERE id=?", (past, o2["id"]))
    v3 = scan(client, pid, ci, BIG, run_id="run-4").json()
    assert v3["decision"] == "gate" and any("expired" in r["message"] for r in v3["reasons"])
    # evidence change invalidates
    o3 = client.post(f"/v1/projects/{pid}/overrides", json={"scan_id": sid, "reason": "third reviewed exception",
                                                            "hours": 1}, headers=H(admin)).json()
    verify(client, inc["id"], score=99)
    v4 = scan(client, pid, ci, BIG, run_id="run-5").json()
    assert v4["decision"] == "gate" and any("evidence changed" in r["message"] for r in v4["reasons"])
    # wrong commit: the override does not apply to other commits
    assert client.delete(f"/v1/projects/{pid}/overrides/{o3['id']}", headers=H(admin)).status_code == 200
    events = [e["action"] for e in client.get(f"/v1/projects/{pid}/audit", headers=H(admin)).json()["events"]]
    assert {"override.created", "override.consumed", "override.revoked", "policy.changed"} <= set(events)


def test_s7_live_mode_without_sync_is_unknown(tmp_path):
    s = Settings(db_path=tmp_path / "live.db", admin_token=OP, snapshot_mode=False)
    client = TestClient(create_app(s))
    pid, admin, ci = new_project(client)
    v = scan(client, pid, ci, TREE).json()
    assert (v["decision"], v["assessment"]) == ("warn", "unknown")
    assert v["data_quality"]["status"] == "stale"
    set_policy(client, pid, admin, mode="enforce")
    v2 = scan(client, pid, ci, TREE).json()
    assert v2["decision"] == "unavailable" and v2["exit_code"] == 3


def test_s11_simulation_is_labelled_and_opt_in(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    verify(client, incident(client, "evil", ["1.0.1"], 95, sim=True)["id"])
    assert scan(client, pid, ci, TREE).json()["findings"] == []
    set_policy(client, pid, admin, include_simulations=True)
    v = scan(client, pid, ci, TREE).json()
    assert "simulation" in v["labels"] and "offline_snapshot" in v["labels"]
    assert v["findings"][0]["is_simulation"]


def test_triage_is_admin_only_and_audited(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    incident(client, "evil", ["1.0.1"], 80)
    scan(client, pid, ci, TREE)
    (alert,) = client.get(f"/v1/projects/{pid}/alerts", headers=H(ci)).json()["alerts"]
    assert alert["triage_status"] == "open"
    url = f"/v1/projects/{pid}/alerts/{alert['id']}/triage"
    assert client.post(url, json={"decision": "reject", "note": "false positive"}, headers=H(ci)).status_code == 403
    r = client.post(url, json={"decision": "reject", "note": "false positive: dev-only path"}, headers=H(admin))
    assert r.json()["triage_status"] == "rejected"
    events = client.get(f"/v1/projects/{pid}/audit", headers=H(admin)).json()["events"]
    assert any(e["action"] == "alert.triage.rejected" for e in events)


def test_alert_delivery_retries_then_fails_without_touching_verdict(env):
    client, app = env
    pid, admin, ci = new_project(client)
    incident(client, "evil", ["1.0.1"], 80)
    v = scan(client, pid, ci, TREE).json()

    class Broken:
        name = "broken"

        def send(self, *a):
            raise ConnectionError("smtp down password=hunter2")

    now = datetime.now(timezone.utc)
    for i in range(3):
        dispatch_pending(app.state.db, Broken(), max_attempts=3, now=now + timedelta(days=i))
    (alert,) = client.get(f"/v1/projects/{pid}/alerts", headers=H(ci)).json()["alerts"]
    assert alert["delivery_status"] == "failed" and alert["attempts"] == 3
    assert "hunter2" not in (alert["last_error"] or "")
    vv = client.get(f"/v1/projects/{pid}/verdicts/{v['verdict_id']}", headers=H(ci)).json()
    assert vv["decision"] == v["decision"]


# ------------------------------------------------------------------ NT-025

def test_s10_lkg_and_pin_patch(env):
    client, _ = env
    pid, admin, ci = new_project(client)
    assert client.get(f"/v1/projects/{pid}/lkg?name=evil&bad=1.0.1", headers=H(ci)).json()["available"] is False
    old = {"root": ["web@1.0.0"], "web@1.0.0": ["evil@1.0.0"]}
    assert scan(client, pid, ci, old, commit=C1).json()["decision"] == "pass"
    incident(client, "evil", ["1.0.1"], 80)
    scan(client, pid, ci, TREE, commit=C2)
    lkg = client.get(f"/v1/projects/{pid}/lkg?name=evil&bad=1.0.1", headers=H(ci)).json()
    assert lkg["available"] and lkg["version"] == "1.0.0" and lkg["provenance"]["commit"] == C1
    pkg = json.dumps({"name": "demo-app", "dependencies": {"web": "^1.0.0"}}, indent=2) + "\n"
    req = {"name": "evil", "version": "1.0.0", "bad_versions": ["1.0.1"], "package_json": pkg}
    assert client.post(f"/v1/projects/{pid}/lkg/patch", json=req, headers=H(admin)).status_code == 403
    set_policy(client, pid, admin, allow_pin_suggestions=True)
    assert client.post(f"/v1/projects/{pid}/lkg/patch", json={**req, "version": "0.9.0"},
                       headers=H(admin)).status_code == 409
    r = client.post(f"/v1/projects/{pid}/lkg/patch", json=req, headers=H(admin)).json()
    assert '+  "overrides": {' in r["patch"] and '"evil": "1.0.0"' in r["patch"]
    assert r["applies_automatically"] is False and r["reverse_patch"]
    # if 1.0.0 becomes suspect too, there is no LKG and no pin
    incident(client, "evil", ["1.0.0"], 80)
    assert client.get(f"/v1/projects/{pid}/lkg?name=evil&bad=1.0.1", headers=H(ci)).json()["available"] is False
    ver = client.get(f"/v1/projects/{pid}/lkg/verify?scan_id={lkg['provenance']['scan_id']}&name=evil&version=1.0.0",
                     headers=H(ci)).json()
    assert ver["consistent"] is True


def test_logs_never_contain_keys(env, capfd):
    import logging

    from nodetrust.obs import configure_logging
    configure_logging("INFO")
    client, _ = env
    pid, admin, ci = new_project(client)
    scan(client, pid, ci, TREE)
    logging.getLogger("nodetrust.test").info("leak attempt %s", ci)
    err = capfd.readouterr().err
    assert ci not in err and admin not in err and OP not in err
