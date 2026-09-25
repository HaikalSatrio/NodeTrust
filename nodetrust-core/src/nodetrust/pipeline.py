"""Scan submission pipeline: SBOM -> scan -> drift -> exposure -> policy -> verdict -> alerts.

Runs in a single transaction so a verdict is never recorded without the scan,
findings, approvals and alerts it is based on. Re-submitting the same SBOM for
the same commit re-evaluates (policy, evidence or approvals may have changed) but
does not duplicate the scan, drift or alerts.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field

from nodetrust import SCHEMA_VERSION
from nodetrust.alerts import raise_alerts
from nodetrust.contracts import DataQuality, Decision, Mode
from nodetrust.exposure.drift import compute_drift
from nodetrust.exposure.matching import match_scan
from nodetrust.exposure.scans import FetchBudget, ScanView, load_scan, store_scan
from nodetrust.forecast import forecast
from nodetrust.freshness import freshness
from nodetrust.graph.blast import reverse_bfs
from nodetrust.graph.centrality import centrality_of
from nodetrust.graph.store import snapshot_id
from nodetrust.obs import correlation, get_logger, log
from nodetrust.policy.config import current_policy
from nodetrust.policy.engine import SEVERITY, evaluate, exit_code_for
from nodetrust.policy.overrides import (approvals_for_scan, consume_override, evidence_fingerprint, find_override,
                                        request_approval)
from nodetrust.sbom.cyclonedx import parse_cyclonedx
from nodetrust.storage import Database, dumps, new_id, utcnow

_log = get_logger("pipeline")


@dataclass
class PipelineConfig:
    required_sources: list[str]
    snapshot_mode: bool
    max_components: int
    traversal_max_nodes: int = 5000
    traversal_max_depth: int = 25
    fetch_budget: FetchBudget = field(default_factory=FetchBudget)


def timeline_for_finding(con: sqlite3.Connection, cfg: PipelineConfig):
    cache: dict[str, dict] = {}

    def _t(f) -> dict:
        v = f.versions[0] if f.versions else None
        key = f"{f.package}@{v}"
        if key not in cache:
            if not v or v == "?":
                cache[key] = {"kind": "heuristic_simulation", "validated": False, "status": "unknown",
                              "reason": "no exact version"}
            else:
                br = reverse_bfs(con, f.package, v, max_nodes=cfg.traversal_max_nodes,
                                 max_depth=cfg.traversal_max_depth)
                c = centrality_of(con, f.package, v)
                cache[key] = forecast(br.by_hop(), centrality=c["betweenness"] if c else None,
                                      truncated=br.truncated)
        return cache[key]

    return _t


def _drift_summary(drift: dict | None) -> dict | None:
    if drift is None:
        return None
    return {"baseline_scan_id": (drift.get("baseline") or {}).get("id"), "added": len(drift["added"]),
            "removed": len(drift["removed"]), "changed": len(drift["changed"]), "first_scan": drift["first_scan"]}


def evaluate_scan(con: sqlite3.Connection, db: Database, *, project: dict, scan: ScanView, cfg: PipelineConfig,
                  actor: str, drift: dict | None = None, reused: bool = False) -> dict:
    policy_ver, policy = current_policy(con, project["id"])
    fresh = freshness(con, required=cfg.required_sources, stale_after_hours=policy.stale_after_hours,
                      snapshot_mode=cfg.snapshot_mode)
    quality = scan.quality
    if quality is DataQuality.COMPLETE and fresh["stale"]:
        quality = DataQuality.STALE
    findings = match_scan(con, scan)
    ev = evaluate(findings, policy=policy, quality=quality,
                  approvals=approvals_for_scan(con, project["id"], scan.id))
    decision = ev.decision
    reasons = list(ev.reasons)

    approvals = []
    for f in ev.findings:
        if f.needs_approval and f.decision is Decision.PENDING_APPROVAL:
            aid = request_approval(con, project_id=project["id"], incident_id=f.incident_id, scan_id=scan.id,
                                   reason=f.reasons[-1]["message"])
            approvals.append(aid)

    fdicts = [f.to_dict() for f in ev.findings]
    fingerprint = evidence_fingerprint(scan.sbom_sha256, fdicts)
    override_info = None
    if policy.mode is Mode.ENFORCE and SEVERITY[decision] >= SEVERITY[Decision.UNAVAILABLE]:
        ovr, rejected = find_override(con, project_id=project["id"], commit_sha=scan.commit_sha,
                                      policy_version=policy_ver, fingerprint=fingerprint, run_id=scan.run_id)
        for r in rejected:
            reasons.append({"code": "override_rejected", "message": f"Override not applied ({r})."})
        if ovr:
            consume_override(con, ovr["id"], scan.run_id)
            override_info = {"id": ovr["id"], "by": ovr["created_by"], "reason": ovr["reason"],
                             "expires_at": ovr["expires_at"], "original_decision": decision.value}
            reasons.append({"code": "override_applied",
                            "message": f"Override {ovr['id']} by {ovr['created_by']} applied for this run: "
                                       f"{ovr['reason']} (original decision: {decision.value}). Findings are kept."})
            db.audit(con, actor=actor, action="override.consumed", project_id=project["id"], target=ovr["id"],
                     detail={"scan_id": scan.id, "run_id": scan.run_id, "original_decision": decision.value},
                     correlation_id=scan.id)
            decision = Decision.WARN

    labels = []
    if any(f.is_simulation for f in ev.findings):
        labels.append("simulation")
    if fresh["mode"] == "snapshot":
        labels.append("offline_snapshot")
    vid = new_id("vrd")
    body = {
        "schema_version": SCHEMA_VERSION,
        "verdict_id": vid,
        "project_id": project["id"],
        "scan": scan.identity(),
        "policy_version": policy_ver,
        "mode": policy.mode.value,
        "decision": decision.value,
        "assessment": ev.assessment,
        "exit_code": exit_code_for(decision),
        "labels": labels,
        "data_quality": {"status": quality.value, "coverage": scan.coverage, "freshness": fresh,
                         "graph_snapshot": snapshot_id(con)},
        "findings": fdicts,
        "reasons": reasons,
        "approvals_pending": approvals,
        "override": override_info,
        "evidence_fingerprint": fingerprint,
        "created_at": utcnow(),
        "notes": ["Risk scores are heuristic, not probabilities.",
                  "A vulnerability advisory is not evidence of compromise.",
                  "Packages not in the graph are unknown, not safe."],
    }
    alerts = raise_alerts(con, project=project, scan_identity=scan.identity(), findings=ev.findings,
                          verdict_id=vid, timeline_for=timeline_for_finding(con, cfg))
    body["alerts_raised"] = alerts
    body["drift"] = _drift_summary(drift)
    body["scan_reused"] = reused
    con.execute("INSERT INTO verdict(id, project_id, scan_id, commit_sha, policy_version, mode, decision, assessment, "
                "body_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (vid, project["id"], scan.id, scan.commit_sha, policy_ver, policy.mode.value, decision.value,
                 ev.assessment, dumps(body), body["created_at"]))
    db.audit(con, actor=actor, action="verdict.issued", project_id=project["id"], target=vid,
             detail={"scan_id": scan.id, "decision": decision.value, "policy_version": policy_ver,
                     "findings": len(fdicts), "alerts": alerts}, correlation_id=scan.id)
    db.bump(con, f"verdicts_{decision.value}")
    return body


def submit_scan(db: Database, cfg: PipelineConfig, *, project: dict, sbom_raw, commit_sha: str, branch: str,
                run_id: str | None, actor: str) -> dict:
    sbom = parse_cyclonedx(sbom_raw, max_components=cfg.max_components)  # raises SbomError -> 422
    with db.transaction() as con:
        scan_id, created = store_scan(con, project_id=project["id"], sbom=sbom, commit_sha=commit_sha, branch=branch,
                                      run_id=run_id, budget=cfg.fetch_budget)
        with correlation(scan_id):
            scan = load_scan(con, scan_id, project["id"])
            if not created and run_id and scan.run_id != run_id:
                scan.run_id = run_id  # this evaluation belongs to the re-run
            drift = compute_drift(con, scan)
            if created:
                db.audit(con, actor=actor, action="scan.received", project_id=project["id"], target=scan_id,
                         detail={"commit": commit_sha, "branch": branch, "components": len(sbom.components),
                                 "quality": sbom.quality().value}, correlation_id=scan_id)
                db.bump(con, "scans_received")
            body = evaluate_scan(con, db, project=project, scan=scan, cfg=cfg, actor=actor, drift=drift,
                                 reused=not created)
    log(_log, logging.INFO, "scan.evaluated", project_id=project["id"], scan_id=scan_id, correlation_id=scan_id,
        decision=body["decision"], findings=len(body["findings"]), reused=not created)
    return body
