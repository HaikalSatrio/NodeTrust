"""Offline demo seed (supports NT-026 dashboard work; the reproducible snapshot
itself is NT-027, owner: Haikal).

Loads the synthetic fixtures, simulates one crawler update, imports a synthetic
advisory, creates two demo projects (one exposed, one clean) and submits scans.
Run the API with NODETRUST_SNAPSHOT_MODE=true so verdicts are labelled
"offline snapshot"; demo incidents are marked simulation.
"""

from __future__ import annotations

import json
from pathlib import Path

from nodetrust.api.auth import create_key, create_project
from nodetrust.contracts import EvidenceStatus
from nodetrust.graph.centrality import compute_and_cache
from nodetrust.graph.store import upsert_packument
from nodetrust.incidents import create_incident, update_evidence
from nodetrust.intel.osv import import_records, iter_dir
from nodetrust.pipeline import PipelineConfig, submit_scan
from nodetrust.policy.config import PolicyConfig, save_policy
from nodetrust.registry.normalize import normalize_packument
from nodetrust.risk.diff import diff_versions
from nodetrust.risk.scoring import score_and_store
from nodetrust.incidents import upsert_crawler_signal
from nodetrust.storage import Database

DEMO_EMAIL = "demo-owner@example.invalid"


def _ingest(db: Database, path: Path, *, signals: bool) -> None:
    rec = normalize_packument(json.loads(path.read_text(encoding="utf-8")))
    with db.transaction() as con:
        res = upsert_packument(con, rec, source="demo-fixture")
        todo = sorted(set(res.new_versions) | {x for x, _, _ in res.integrity_changes})
        for delta in diff_versions(con, rec.name, todo):
            score = score_and_store(con, delta)
            if signals:
                upsert_crawler_signal(con, score)


def seed_demo(db: Database, fixtures: Path) -> dict:
    # Only ever into an empty database: seeding next to real data would mix synthetic scans and
    # simulated incidents with real ones.
    with db.read() as con:
        for table in ("project", "incident", "advisory", "pkg_version"):
            if con.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                raise SystemExit(f"this database already has data ({table}); the demo needs a fresh "
                                 "NODETRUST_DB_PATH")
    for p in sorted((fixtures / "packuments").glob("*.json")):
        _ingest(db, p, signals=False)  # baseline ingest: history is not news
    _ingest(db, fixtures / "update" / "ntdemo-utils.json", signals=True)
    import_records(db, iter_dir(fixtures / "osv"), source="demo-fixture")
    with db.transaction() as con:
        compute_and_cache(con)
        # Mark crawler output from the demo as simulation, and add one human-"verified"
        # simulated incident so the enforce/approval path can be shown.
        con.execute("UPDATE incident SET is_simulation=1 WHERE name LIKE 'ntdemo-%' OR name LIKE '@ntdemo/%'")
        sim = create_incident(con, title="SIMULATION: compromised ntdemo-utils@2.1.1 (demo scenario)",
                              name="ntdemo-utils", affected={"versions": ["2.1.1"]}, risk_score=92,
                              source="manual", is_simulation=True,
                              notes="Synthetic scenario for the offline demo. Not a real incident.")
        update_evidence(con, sim["id"], status=EvidenceStatus.VERIFIED)
        projects = {}
        for name, policy in (
            ("demo-exposed", PolicyConfig(mode="enforce", include_simulations=True,
                                          preauthorize_gate_verified_critical=True,
                                          preauthorize_hold_large_radius=True, allow_pin_suggestions=True)),
            ("demo-clean", PolicyConfig(include_simulations=True)),
        ):
            proj, admin = create_project(con, name=name, alert_email=DEMO_EMAIL, created_by="demo")
            save_policy(con, proj["id"], policy, "demo")
            ci, _ = create_key(con, project_id=proj["id"], role="ci", label="demo ci", created_by="demo")
            projects[name] = {"project": proj, "admin_key": admin, "ci_key": ci}

    cfg = PipelineConfig(required_sources=["feed:npm", "intel:osv"], snapshot_mode=True, max_components=50_000)
    sb = fixtures / "sbom"
    results = {}
    runs = [("demo-exposed", "exposed-old", "1111111111111111111111111111111111111111", "run-demo-1"),
            ("demo-exposed", "exposed-new", "2222222222222222222222222222222222222222", "run-demo-2"),
            ("demo-clean", "clean", "3333333333333333333333333333333333333333", "run-demo-3")]
    for pname, fname, commit, run in runs:
        v = submit_scan(db, cfg, project=projects[pname]["project"],
                        sbom_raw=json.loads((sb / f"{fname}.cdx.json").read_text(encoding="utf-8")),
                        commit_sha=commit, branch="main", run_id=run, actor="demo")
        results[f"{pname}/{fname}"] = {"decision": v["decision"], "findings": len(v["findings"]),
                                       "labels": v["labels"], "scan_id": v["scan"]["scan_id"]}
    return {"projects": {k: {"id": v["project"]["id"], "admin_key": v["admin_key"], "ci_key": v["ci_key"]}
                         for k, v in projects.items()},
            "scans": results,
            "note": "Demo keys for a local, synthetic dataset only. Start the API with NODETRUST_SNAPSHOT_MODE=true."}
