"""FastAPI application (NT-017 API, plus endpoints for NT-018..026 and NT-042).

Every project route goes through `require_project`, which enforces that a key
can only see its own project. Operator routes use the instance admin token.
See docs/api.md for the full contract.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from nodetrust import SCHEMA_VERSION, __version__
from nodetrust.alerts import list_alerts, triage
from nodetrust.api import schemas as S
from nodetrust.api.auth import (AuthThrottle, Principal, create_key, create_project, require_operator,
                                require_principal, require_project)
from nodetrust.config import Settings
from nodetrust.exposure.drift import compute_drift
from nodetrust.exposure.report import baseline_report
from nodetrust.exposure.scans import FetchBudget, latest_scans, load_scan
from nodetrust.forecast import forecast
from nodetrust.freshness import freshness
from nodetrust.graph.blast import reverse_bfs
from nodetrust.graph.centrality import centrality_of, compute_and_cache
from nodetrust.graph.store import graph_stats
from nodetrust.incidents import create_incident, get_incident, list_incidents, update_evidence
from nodetrust.intel.osv import import_records
from nodetrust.lkg import find_lkg, pin_patch, verify_pin
from nodetrust.obs import correlation, get_logger, log
from nodetrust.pipeline import PipelineConfig, submit_scan
from nodetrust.policy.config import PolicyConfig, current_policy, save_policy
from nodetrust.policy.overrides import OverrideError, create_override, decide_approval, revoke_override
from nodetrust.sbom.cyclonedx import SbomError
from nodetrust.storage import Database, utcnow

_log = get_logger("api")


def _err(status: int, code: str, message: str, details=None) -> JSONResponse:
    body = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(body, status_code=status)


def create_app(settings: Settings | None = None, db: Database | None = None) -> FastAPI:
    settings = settings or Settings()
    docs = settings.expose_api_docs
    app = FastAPI(title="NodeTrust core", version=__version__, redoc_url=None,
                  docs_url="/docs" if docs else None, openapi_url="/openapi.json" if docs else None)
    app.state.settings = settings
    app.state.auth_throttle = AuthThrottle(settings.auth_max_failures, settings.auth_failure_window_s)
    app.state.db = db or Database(settings.db_path)
    app.state.admin_token = settings.admin_token.get_secret_value() if settings.admin_token else None
    app.state.pipeline = PipelineConfig(
        required_sources=[s.strip() for s in settings.required_sources.split(",") if s.strip()],
        snapshot_mode=settings.snapshot_mode, max_components=settings.max_sbom_components,
        traversal_max_nodes=settings.traversal_max_nodes, traversal_max_depth=settings.traversal_max_depth,
        fetch_budget=FetchBudget(per_scan=settings.fetch_budget_per_scan,
                                 max_pending=settings.max_pending_sbom_fetches,
                                 cooldown_hours=settings.sbom_fetch_cooldown_hours))
    dbh: Database = app.state.db

    # ------------------------------------------------------------ middleware / errors
    @app.middleware("http")
    async def _request_context(request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        rid = "".join(ch for ch in rid if ch.isalnum() or ch in "-_")[:64] or uuid.uuid4().hex[:16]
        t0 = time.perf_counter()
        with correlation(rid):
            try:
                response = await call_next(request)
            except Exception:  # noqa: BLE001
                _log.exception("request.unhandled", extra={"fields": {"path": request.url.path}})
                response = _err(500, "internal_error", "internal error", {"request_id": rid})
            response.headers["x-request-id"] = rid
            response.headers["x-content-type-options"] = "nosniff"
            response.headers["referrer-policy"] = "no-referrer"
            if request.url.path.startswith("/dashboard"):
                response.headers["content-security-policy"] = (
                    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
                response.headers["x-frame-options"] = "DENY"
            else:
                response.headers["cache-control"] = "no-store"
            log(_log, logging.INFO, "request", method=request.method, path=request.url.path,
                status=response.status_code, ms=round((time.perf_counter() - t0) * 1000, 1))
            return response

    @app.exception_handler(HTTPException)
    async def _http_exc(request: Request, exc: HTTPException):
        resp = _err(exc.status_code, {401: "unauthorized", 403: "forbidden", 404: "not_found",
                                      409: "conflict", 413: "payload_too_large",
                                      429: "rate_limited"}.get(exc.status_code, "error"),
                    str(exc.detail))
        for k, v in (exc.headers or {}).items():
            resp.headers[k] = v
        return resp

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        details = [{"loc": [str(x) for x in e.get("loc", [])], "msg": e.get("msg")} for e in exc.errors()][:20]
        return _err(422, "invalid_request", "request body failed validation", details)

    def principal(request: Request) -> Principal:
        return require_principal(request)

    def project_row(con, pid: str) -> dict:
        r = con.execute("SELECT * FROM project WHERE id=?", (pid,)).fetchone()
        if r is None:
            raise HTTPException(404, "project not found")
        return dict(r)

    # ------------------------------------------------------------ health (NT-042)
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        try:
            with dbh.read() as con:
                con.execute("SELECT 1").fetchone()
                rev = con.execute("SELECT value FROM meta WHERE key='schema_revision'").fetchone()[0]
        except Exception:  # noqa: BLE001
            return _err(503, "not_ready", "database unavailable")
        return {"status": "ready", "schema_revision": int(rev), "schema_version": SCHEMA_VERSION}

    @app.get("/v1/meta")
    def meta():
        return {"version": __version__, "schema_version": SCHEMA_VERSION, "snapshot_mode": settings.snapshot_mode,
                "network_enabled": settings.allow_network}

    @app.get("/v1/metrics")
    def metrics(p: Principal = Depends(principal)):
        require_operator(p)
        with dbh.read() as con:
            counters = {r["name"]: r["value"] for r in con.execute("SELECT name, value FROM counter ORDER BY name")}
            jobs = {r["status"]: r["n"] for r in con.execute(
                "SELECT status, COUNT(*) AS n FROM fetch_job GROUP BY status")}
            sync = {r["source"]: {"last_success_at": r["last_success_at"], "last_attempt_at": r["last_attempt_at"],
                                  "last_error": r["last_error"], "detail": json.loads(r["detail_json"])}
                    for r in con.execute("SELECT * FROM sync_status ORDER BY source")}
            alerts = {r["delivery_status"]: r["n"] for r in con.execute(
                "SELECT delivery_status, COUNT(*) AS n FROM alert GROUP BY delivery_status")}
            fresh = freshness(con, required=app.state.pipeline.required_sources, stale_after_hours=24.0,
                              snapshot_mode=settings.snapshot_mode)
            cp = con.execute("SELECT feed, seq, updated_at FROM feed_checkpoint").fetchall()
        now = datetime.now(timezone.utc)
        feed_lag = {r["feed"]: {"seq": r["seq"], "checkpoint_age_s": round(
            (now - datetime.fromisoformat(r["updated_at"].replace("Z", "+00:00"))).total_seconds())} for r in cp}
        return {"counters": counters, "fetch_jobs": jobs, "sync": sync, "alerts": alerts, "freshness": fresh,
                "feed": feed_lag}

    # ------------------------------------------------------------ operator
    @app.post("/v1/projects", status_code=201)
    def create_project_ep(body: S.ProjectCreate, p: Principal = Depends(principal)):
        require_operator(p)
        with dbh.transaction() as con:
            proj, key = create_project(con, name=body.name, alert_email=body.alert_email, created_by=p.actor)
            save_policy(con, proj["id"], PolicyConfig(), p.actor)
            dbh.audit(con, actor=p.actor, action="project.created", project_id=proj["id"], target=proj["id"])
        return {"project": proj, "admin_key": key,
                "note": "Store the admin key now; it is not shown again."}

    @app.get("/v1/projects")
    def list_projects(p: Principal = Depends(principal)):
        require_operator(p)
        with dbh.read() as con:
            return {"projects": [dict(r) for r in con.execute("SELECT id, name, created_at FROM project ORDER BY created_at")]}

    @app.post("/v1/incidents", status_code=201)
    def create_incident_ep(body: S.IncidentCreate, p: Principal = Depends(principal)):
        require_operator(p)
        with dbh.transaction() as con:
            try:
                inc = create_incident(con, title=body.title, name=body.package, affected=body.affected.model_dump(),
                                      risk_score=body.risk_score, source="manual", is_simulation=body.is_simulation,
                                      detected_at=body.detected_at, notes=body.notes)
            except ValueError as e:
                raise HTTPException(422, str(e)) from e
            dbh.audit(con, actor=p.actor, action="incident.created", target=inc["id"],
                      detail={"package": inc["name"], "score": inc["risk_score"], "simulation": inc["is_simulation"]})
        return inc

    @app.get("/v1/incidents")
    def list_incidents_ep(p: Principal = Depends(principal), include_rejected: bool = False,
                          package: str | None = Query(None, max_length=214),
                          limit: int = Query(500, ge=1, le=5000)):
        require_operator(p)
        with dbh.read() as con:
            rows = list_incidents(con, name=package.lower() if package else None,
                                  include_rejected=include_rejected, limit=limit)
            return {"incidents": rows, "limit": limit}

    @app.patch("/v1/incidents/{incident_id}")
    def update_incident_ep(incident_id: str, body: S.IncidentUpdate, p: Principal = Depends(principal)):
        require_operator(p)
        with dbh.transaction() as con:
            try:
                before = get_incident(con, incident_id)
                inc = update_evidence(con, incident_id, status=body.evidence_status, risk_score=body.risk_score,
                                      notes=body.notes)
            except KeyError:
                raise HTTPException(404, "incident not found") from None
            dbh.audit(con, actor=p.actor, action="incident.evidence_updated", target=incident_id,
                      detail={"from": {"status": before["evidence_status"], "score": before["risk_score"]},
                              "to": {"status": inc["evidence_status"], "score": inc["risk_score"]},
                              "evidence_version": inc["evidence_version"]})
        return inc

    @app.post("/v1/intel/osv/records")
    async def osv_records(request: Request, p: Principal = Depends(principal)):
        require_operator(p)
        raw = await request.body()
        if len(raw) > 50 * 1024 * 1024:
            raise HTTPException(413, "payload too large")
        try:
            docs = json.loads(raw)
        except ValueError:
            raise HTTPException(422, "body must be a JSON array of OSV records") from None
        if not isinstance(docs, list):
            raise HTTPException(422, "body must be a JSON array of OSV records")
        rep = await run_in_threadpool(import_records, dbh, docs, source="api-upload")
        return rep.__dict__

    @app.get("/v1/watchlist")
    def get_watchlist(p: Principal = Depends(principal)):
        require_operator(p)
        with dbh.read() as con:
            return {"names": [r["name"] for r in con.execute("SELECT name FROM watchlist ORDER BY name")]}

    @app.post("/v1/watchlist")
    def add_watchlist(body: S.Watchlist, p: Principal = Depends(principal)):
        require_operator(p)
        from nodetrust.registry.feed import enqueue_fetch

        with dbh.transaction() as con:
            for n in body.names:
                con.execute("INSERT OR IGNORE INTO watchlist(ecosystem, name, reason, added_at) VALUES "
                            "('npm', ?, 'operator', ?)", (n, utcnow()))
                enqueue_fetch(con, n, "watchlist")
            dbh.audit(con, actor=p.actor, action="watchlist.added", detail={"count": len(body.names)})
        return {"added": len(body.names)}

    @app.post("/v1/graph/centrality")
    def recompute_centrality(p: Principal = Depends(principal)):
        require_operator(p)
        with dbh.transaction() as con:
            return compute_and_cache(con)

    # ------------------------------------------------------------ public graph (any principal)
    @app.get("/v1/graph/stats")
    def graph_stats_ep(p: Principal = Depends(principal)):
        with dbh.read() as con:
            return graph_stats(con)

    @app.get("/v1/graph/blast")
    def graph_blast(name: str, version: str, p: Principal = Depends(principal),
                    max_nodes: int = Query(default=1000, ge=1, le=5000)):
        with dbh.read() as con:
            br = reverse_bfs(con, name.lower(), version, max_nodes=max_nodes,
                             max_depth=settings.traversal_max_depth)
            c = centrality_of(con, name.lower(), version)
        out = br.to_dict()
        out["dependents"] = out["dependents"][:500]
        out["centrality"] = c
        out["forecast"] = forecast(br.by_hop(), centrality=c["betweenness"] if c else None, truncated=br.truncated)
        return out

    # ------------------------------------------------------------ project
    @app.get("/v1/projects/{pid}")
    def get_project(pid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            proj = project_row(con, pid)
            ver, pol = current_policy(con, pid)
        return {"project": proj, "policy_version": ver, "policy": pol.model_dump(mode="json"), "you": p.actor}

    @app.put("/v1/projects/{pid}/settings")
    def project_settings(pid: str, body: S.ProjectSettings, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.transaction() as con:
            con.execute("UPDATE project SET alert_email=? WHERE id=?", (body.alert_email, pid))
            dbh.audit(con, actor=p.actor, action="project.settings", project_id=pid,
                      detail={"alert_email_set": body.alert_email is not None})
            return project_row(con, pid)

    @app.get("/v1/projects/{pid}/policy")
    def get_policy(pid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            ver, pol = current_policy(con, pid)
            history = [dict(r) for r in con.execute(
                "SELECT version, created_at, created_by FROM policy WHERE project_id=? ORDER BY version DESC", (pid,))]
        return {"version": ver, "policy": pol.model_dump(mode="json"), "history": history}

    @app.put("/v1/projects/{pid}/policy")
    def put_policy(pid: str, body: PolicyConfig, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.transaction() as con:
            old_ver, old = current_policy(con, pid)
            ver = save_policy(con, pid, body, p.actor)
            changed = {k: {"from": v, "to": body.model_dump(mode="json")[k]}
                       for k, v in old.model_dump(mode="json").items() if body.model_dump(mode="json")[k] != v}
            dbh.audit(con, actor=p.actor, action="policy.changed", project_id=pid, target=f"policy:{ver}",
                      detail={"from_version": old_ver, "to_version": ver, "changes": changed})
        return {"version": ver, "policy": body.model_dump(mode="json")}

    @app.get("/v1/projects/{pid}/keys")
    def list_keys(pid: str, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.read() as con:
            return {"keys": [dict(r) for r in con.execute(
                "SELECT id, role, label, created_at, created_by, revoked_at FROM api_key WHERE project_id=? "
                "ORDER BY created_at", (pid,))]}

    @app.post("/v1/projects/{pid}/keys", status_code=201)
    def new_key(pid: str, body: S.KeyCreate, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.transaction() as con:
            key, meta_ = create_key(con, project_id=pid, role=body.role, label=body.label, created_by=p.actor)
            dbh.audit(con, actor=p.actor, action="key.created", project_id=pid, target=meta_["id"],
                      detail={"role": body.role, "label": body.label})
        return {"key": key, **meta_, "note": "Store this key now; it is not shown again."}

    @app.delete("/v1/projects/{pid}/keys/{kid}")
    def revoke_key(pid: str, kid: str, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.transaction() as con:
            cur = con.execute("UPDATE api_key SET revoked_at=? WHERE id=? AND project_id=? "
                              "AND revoked_at IS NULL", (utcnow(), kid, pid))
            if cur.rowcount != 1:
                raise HTTPException(404, "key not found or already revoked")
            dbh.audit(con, actor=p.actor, action="key.revoked", project_id=pid, target=kid)
        return {"revoked": kid}

    # scans / verdicts ---------------------------------------------------------
    @app.post("/v1/projects/{pid}/scans")
    async def submit(pid: str, request: Request, p: Principal = Depends(principal)):
        require_project(p, pid)
        declared = request.headers.get("content-length")
        limit = settings.max_sbom_bytes + 4096  # envelope: commit, branch, run_id
        if declared and declared.isdigit() and int(declared) > limit:
            raise HTTPException(413, f"payload exceeds {settings.max_sbom_bytes} bytes")
        raw = await request.body()
        if len(raw) > limit:
            raise HTTPException(413, f"payload exceeds {settings.max_sbom_bytes} bytes")
        try:
            body = S.ScanSubmit.model_validate_json(raw)
        except ValueError as e:
            details = [{"loc": [str(x) for x in err.get("loc", [])], "msg": err.get("msg")}
                       for err in getattr(e, "errors", lambda: [])()][:20]
            return _err(422, "invalid_request", "scan submission failed validation", details or str(e)[:500])
        with dbh.read() as con:
            proj = project_row(con, pid)
        try:
            verdict = await run_in_threadpool(submit_scan, dbh, app.state.pipeline, project=proj,
                                              sbom_raw=body.sbom, commit_sha=body.commit, branch=body.branch,
                                              run_id=body.run_id, actor=p.actor)
        except SbomError as e:
            return _err(422, "invalid_sbom", "SBOM rejected", e.problems[:50])
        return verdict

    @app.get("/v1/projects/{pid}/scans")
    def scans(pid: str, p: Principal = Depends(principal), limit: int = Query(default=20, ge=1, le=200)):
        require_project(p, pid)
        with dbh.read() as con:
            return {"scans": latest_scans(con, pid, limit)}

    def _scan(con, pid, sid):
        s = load_scan(con, sid, pid)
        if s is None:
            raise HTTPException(404, "scan not found")
        return s

    @app.get("/v1/projects/{pid}/scans/{sid}")
    def scan_detail(pid: str, sid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            s = _scan(con, pid, sid)
            return {**s.identity(), "quality": s.quality.value, "coverage": s.coverage,
                    "components": len(s.components), "edges": len(s.edges)}

    @app.get("/v1/projects/{pid}/scans/{sid}/report")
    def scan_report(pid: str, sid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            return baseline_report(con, _scan(con, pid, sid))

    @app.get("/v1/projects/{pid}/scans/{sid}/drift")
    def scan_drift(pid: str, sid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.transaction() as con:  # computes lazily for scans stored before drift existed
            return compute_drift(con, _scan(con, pid, sid))

    @app.get("/v1/projects/{pid}/scans/{sid}/graph")
    def scan_graph(pid: str, sid: str, p: Principal = Depends(principal),
                   limit: int = Query(default=400, ge=10, le=2000)):
        require_project(p, pid)
        with dbh.read() as con:
            s = _scan(con, pid, sid)
        nodes = [{"id": s.root_ref, "label": "(project root)", "root": True}]
        for ref, c in s.components.items():
            nodes.append({"id": ref, "label": s.label(ref), "name": c["name"], "version": c["version"],
                          "status": c["status"], "direct": bool(c["is_direct"]), "ecosystem": c["ecosystem"]})
        truncated = len(nodes) > limit
        keep = {n["id"] for n in nodes[:limit]}
        edges = [{"from": a, "to": b} for a, b in sorted(s.edges) if a in keep and b in keep]
        return {"scan_id": sid, "nodes": nodes[:limit], "edges": edges, "truncated": truncated,
                "total_nodes": len(nodes)}

    @app.get("/v1/projects/{pid}/scans/{sid}/verdict")
    def scan_verdict(pid: str, sid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            r = con.execute("SELECT body_json FROM verdict WHERE project_id=? AND scan_id=? "
                            "ORDER BY created_at DESC, rowid DESC LIMIT 1", (pid, sid)).fetchone()
        if r is None:
            raise HTTPException(404, "verdict not found")
        return json.loads(r["body_json"])

    @app.get("/v1/projects/{pid}/verdicts/{vid}")
    def verdict(pid: str, vid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            r = con.execute("SELECT body_json FROM verdict WHERE project_id=? AND id=?", (pid, vid)).fetchone()
        if r is None:
            raise HTTPException(404, "verdict not found")
        return json.loads(r["body_json"])

    # alerts / triage / approvals / overrides -----------------------------------
    @app.get("/v1/projects/{pid}/alerts")
    def alerts(pid: str, p: Principal = Depends(principal), limit: int = Query(default=100, ge=1, le=500)):
        require_project(p, pid)
        with dbh.read() as con:
            return {"alerts": list_alerts(con, pid, limit)}

    @app.post("/v1/projects/{pid}/alerts/{aid}/triage")
    def triage_ep(pid: str, aid: str, body: S.TriageDecision, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.transaction() as con:
            try:
                res = triage(con, project_id=pid, alert_id=aid, decision=body.decision, actor=p.actor, note=body.note)
            except KeyError:
                raise HTTPException(404, "alert not found") from None
            dbh.audit(con, actor=p.actor, action=f"alert.triage.{res['triage_status']}", project_id=pid, target=aid,
                      detail=res, correlation_id=aid)
        return res

    @app.get("/v1/projects/{pid}/approvals")
    def approvals(pid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            return {"approvals": [dict(r) for r in con.execute(
                "SELECT * FROM approval WHERE project_id=? ORDER BY requested_at DESC", (pid,))]}

    @app.post("/v1/projects/{pid}/approvals/{apr_id}")
    def decide(pid: str, apr_id: str, body: S.ApprovalDecision, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.transaction() as con:
            try:
                res = decide_approval(con, project_id=pid, approval_id=apr_id, decision=body.decision,
                                      actor=p.actor, note=body.note)
            except KeyError:
                raise HTTPException(404, "approval not found") from None
            except ValueError as e:
                raise HTTPException(409, str(e)) from e
            dbh.audit(con, actor=p.actor, action=f"approval.{body.decision}", project_id=pid, target=apr_id,
                      detail={"incident_id": res["incident_id"], "scan_id": res["scan_id"], "note": body.note})
        return res

    @app.get("/v1/projects/{pid}/overrides")
    def overrides(pid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            return {"overrides": [dict(r) for r in con.execute(
                "SELECT id, commit_sha, policy_version, incident_id, scan_id, reason, created_by, created_at, "
                "expires_at, consumed_at, consumed_run_id, revoked_at FROM override WHERE project_id=? "
                "ORDER BY created_at DESC", (pid,))]}

    @app.post("/v1/projects/{pid}/overrides", status_code=201)
    def new_override(pid: str, body: S.OverrideCreate, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.transaction() as con:
            _scan(con, pid, body.scan_id)
            _, pol = current_policy(con, pid)
            try:
                o = create_override(con, project_id=pid, scan_id=body.scan_id, reason=body.reason, actor=p.actor,
                                    hours=body.hours, max_hours=pol.override_max_hours, incident_id=body.incident_id)
            except OverrideError as e:
                raise HTTPException(422, str(e)) from e
            dbh.audit(con, actor=p.actor, action="override.created", project_id=pid, target=o["id"],
                      detail={"scan_id": body.scan_id, "commit": o["commit_sha"], "hours": body.hours,
                              "reason": body.reason, "expires_at": o["expires_at"]})
        return o

    @app.delete("/v1/projects/{pid}/overrides/{oid}")
    def del_override(pid: str, oid: str, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.transaction() as con:
            if not revoke_override(con, pid, oid):
                raise HTTPException(404, "override not found or already revoked")
            dbh.audit(con, actor=p.actor, action="override.revoked", project_id=pid, target=oid)
        return {"revoked": oid}

    # LKG (NT-025) ------------------------------------------------------------
    @app.get("/v1/projects/{pid}/lkg")
    def lkg(pid: str, name: str, bad: str = "", p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            _, pol = current_policy(con, pid)
            return find_lkg(con, project_id=pid, name=name.lower(),
                            bad_versions={b.strip() for b in bad.split(",") if b.strip()},
                            include_simulations=pol.include_simulations)

    @app.post("/v1/projects/{pid}/lkg/patch")
    def lkg_patch(pid: str, body: S.PinRequest, p: Principal = Depends(principal)):
        require_project(p, pid, ("admin",))
        with dbh.transaction() as con:
            _, pol = current_policy(con, pid)
            if not pol.allow_pin_suggestions:
                raise HTTPException(403, "pin suggestions are disabled by project policy (allow_pin_suggestions)")
            cand = find_lkg(con, project_id=pid, name=body.name.lower(), bad_versions=set(body.bad_versions),
                            include_simulations=pol.include_simulations)
            if not cand["available"]:
                raise HTTPException(409, cand["message"])
            if cand["version"] != body.version:
                raise HTTPException(409, f"requested version is not the current last-known-good ({cand['version']})")
            try:
                patch = pin_patch(body.package_json, body.name.lower(), body.version)
            except ValueError as e:
                raise HTTPException(422, str(e)) from e
            dbh.audit(con, actor=p.actor, action="lkg.patch_drafted", project_id=pid, target=body.name,
                      detail={"version": body.version, "provenance": cand["provenance"]})
        return {"lkg": cand, **patch}

    @app.get("/v1/projects/{pid}/lkg/verify")
    def lkg_verify(pid: str, scan_id: str, name: str, version: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            _scan(con, pid, scan_id)
            return verify_pin(con, project_id=pid, scan_id=scan_id, name=name.lower(), version=version)

    @app.get("/v1/projects/{pid}/audit")
    def audit(pid: str, p: Principal = Depends(principal), limit: int = Query(default=200, ge=1, le=1000)):
        require_project(p, pid, ("admin",))
        with dbh.read() as con:
            rows = con.execute("SELECT * FROM audit WHERE project_id=? ORDER BY id DESC LIMIT ?", (pid, limit))
            return {"events": [{**dict(r), "detail": json.loads(r["detail_json"])} for r in rows]}

    @app.get("/v1/projects/{pid}/freshness")
    def project_freshness(pid: str, p: Principal = Depends(principal)):
        require_project(p, pid)
        with dbh.read() as con:
            _, pol = current_policy(con, pid)
            return freshness(con, required=app.state.pipeline.required_sources,
                             stale_after_hours=pol.stale_after_hours, snapshot_mode=settings.snapshot_mode)

    # ------------------------------------------------------------ dashboard (NT-026)
    static_dir = Path(str(resources.files("nodetrust").joinpath("dashboard", "static")))
    app.mount("/dashboard", StaticFiles(directory=static_dir, html=True), name="dashboard")

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/dashboard/")

    return app
