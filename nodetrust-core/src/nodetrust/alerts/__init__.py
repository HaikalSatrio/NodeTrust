"""Targeted alerts and minimal triage (NT-023).

- Alerts are raised only for findings the policy marks `notify` AND whose exposure
  is proven (exact version in this project's scan). UNKNOWN exposure is shown on
  the dashboard/CI, never e-mailed. Projects that are not exposed get nothing.
- De-duplication key (D03): project + incident + evidence version + material
  status (tier/decision/evidence). Re-submitting a scan does not re-send;
  a change in severity or evidence does.
- Delivery is decoupled from the verdict: a failed send is retried with backoff
  and never changes the verdict.
- Triage: a project admin confirms or rejects; the decision is audited.
- One channel (e-mail) in the MVP. The default sender writes .eml files to an
  outbox directory (offline); SMTP is used only when configured AND network is
  explicitly allowed. SMTP always upgrades with STARTTLS and verifies the server
  certificate before sending credentials; there is no plaintext fallback.
"""

from __future__ import annotations

import hashlib
import json
import logging
import smtplib
import sqlite3
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Protocol

from nodetrust.obs import get_logger, log, redact
from nodetrust.storage import Database, dumps, new_id, parse_ts, utcnow

_log = get_logger("alerts")


class Sender(Protocol):
    name: str

    def send(self, to: str, subject: str, body: str, headers: dict[str, str]) -> None: ...


class OutboxSender:
    name = "outbox"

    def __init__(self, directory: Path, sender: str = "nodetrust@localhost"):
        self.dir = Path(directory)
        self.sender = sender

    def send(self, to, subject, body, headers):
        self.dir.mkdir(parents=True, exist_ok=True)
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, to, subject
        for k, v in headers.items():
            msg[k] = v
        msg.set_content(body)
        name = f"{headers.get('X-NodeTrust-Alert', 'alert')}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}.eml"
        (self.dir / name).write_bytes(bytes(msg))


class SmtpSender:
    name = "smtp"

    def __init__(self, host: str, port: int, user: str | None, password: str | None, sender: str, *,
                 allow_network: bool, timeout: float = 20.0, ssl_context: ssl.SSLContext | None = None):
        if not allow_network:
            raise RuntimeError("SMTP delivery requires NODETRUST_ALLOW_NETWORK=true")
        self.host, self.port, self.user, self.password, self.sender, self.timeout = host, port, user, password, sender, timeout
        # smtplib's own default for starttls() does not verify the certificate, which would hand
        # the SMTP password to anyone in the middle. Always verify (system CAs unless told otherwise).
        self.ssl_context = ssl_context or ssl.create_default_context()

    def send(self, to, subject, body, headers):
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, to, subject
        for k, v in headers.items():
            msg[k] = v
        msg.set_content(body)
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
            s.starttls(context=self.ssl_context)
            if self.user and self.password:
                s.login(self.user, self.password)
            s.send_message(msg)


def dedup_key(project_id: str, incident_id: str, evidence_version: int, status: str) -> str:
    return hashlib.sha256(f"{project_id}|{incident_id}|{evidence_version}|{status}".encode()).hexdigest()


def _recommendation(f) -> str:
    if f.recommendation:
        return f.recommendation
    return {"WATCH": "Review the change when convenient; no action required by policy.",
            "INVESTIGATE": "Triage: check the evidence and whether the affected version is actually used.",
            "CRITICAL": "Verify the evidence and exposure; follow the project's incident process."}.get(f.tier.value, "")


def raise_alerts(con: sqlite3.Connection, *, project: dict, scan_identity: dict, findings, verdict_id: str,
                 timeline_for) -> list[str]:
    """Insert alert rows for notify-worthy findings. `timeline_for(finding)` returns the
    forecast/timeline dict (kept injectable so tests need no graph)."""
    from nodetrust.contracts import ExposureStatus

    created = []
    for f in findings:
        if not f.notify or f.exposure is not ExposureStatus.EXPOSED:
            continue
        status = f"{f.tier.value}:{f.decision.value}:{f.evidence_status.value}"
        key = dedup_key(project["id"], f.incident_id, f.evidence_version, status)
        if con.execute("SELECT 1 FROM alert WHERE dedup_key=?", (key,)).fetchone():
            continue
        inc = con.execute("SELECT detected_at, source_ref FROM incident WHERE id=?", (f.incident_id,)).fetchone()
        aid = new_id("alr")
        payload = {
            "alert_id": aid,
            "project": {"id": project["id"], "name": project["name"]},
            "incident": {"id": f.incident_id, "title": f.title, "source": f.source,
                         "source_ref": inc["source_ref"] if inc else None, "tier": f.tier.value,
                         "risk_score": f.risk_score, "score_kind": "heuristic (not a probability)",
                         "evidence_status": f.evidence_status.value, "evidence_version": f.evidence_version,
                         "is_simulation": f.is_simulation},
            "exposure": {"package": f.package, "versions": f.versions, "paths": f.paths, "radius": f.radius},
            "scan": scan_identity,
            "verdict_id": verdict_id,
            "decision": f.decision.value,
            "timeline": {"detected_at": inc["detected_at"] if inc else None,
                         "scan_received_at": scan_identity.get("received_at"), "forecast": timeline_for(f)},
            "confidence": {"evidence": f.evidence_status.value,
                           "score": "heuristic weights, uncalibrated",
                           "forecast": "heuristic simulation, not validated"},
            "recommendation": _recommendation(f),
        }
        to = project.get("alert_email")
        now = utcnow()
        con.execute(
            "INSERT INTO alert(id, project_id, incident_id, dedup_key, tier, channel, delivery_status, attempts, "
            "next_attempt_at, triage_status, payload_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,0,?,?,?,?,?)",
            (aid, project["id"], f.incident_id, key, f.tier.value, "email",
             "pending" if to else "no_recipient", now if to else None,
             "open" if f.triage == "pending" or f.tier.value in ("INVESTIGATE", "CRITICAL") else "none",
             dumps(payload), now, now))
        created.append(aid)
    return created


def render_email(payload: dict) -> tuple[str, str]:
    inc, exp = payload["incident"], payload["exposure"]
    sim = "[SIMULATION] " if inc["is_simulation"] else ""
    subject = f"{sim}[NodeTrust][{inc['tier']}] {exp['package']} in {payload['project']['name']}"
    lines = [
        f"{sim}NodeTrust alert {payload['alert_id']}",
        "",
        f"Incident: {inc['title']} ({inc['id']}, source: {inc['source']})",
        f"Tier: {inc['tier']} - score {inc['risk_score']} ({inc['score_kind']})",
        f"Evidence: {inc['evidence_status']} (version {inc['evidence_version']})",
        f"Decision for this build: {payload['decision']}",
        "",
        f"Affected package in your project: {exp['package']} {', '.join(exp['versions'])}",
        "Dependency paths from your project root:",
        *[f"  - {' -> '.join(p)}" for p in exp["paths"][:5]],
        f"Radius in this project: {exp['radius'].get('status')} "
        f"({exp['radius'].get('affected_versions')}/{exp['radius'].get('total_versions')} versions)",
        "",
        f"Scan: commit {payload['scan'].get('commit')} on {payload['scan'].get('branch')} "
        f"(scan {payload['scan'].get('scan_id')}, received {payload['scan'].get('received_at')})",
        f"Detected at: {payload['timeline'].get('detected_at')}",
    ]
    fc = payload["timeline"].get("forecast") or {}
    if fc.get("status") == "ok":
        lines.append("Propagation (heuristic simulation, not validated): " + ", ".join(
            f"T+{h['hours']}h ~{h['expected']}" for h in fc["horizons"]))
    lines += ["", f"Recommendation: {payload['recommendation']}", "",
              "Confidence: evidence status as above; scores are heuristic; forecasts are not validated.",
              "Triage this alert in the NodeTrust dashboard."]
    return subject, "\n".join(lines)


def dispatch_pending(db: Database, sender: Sender, *, max_attempts: int = 5, now: datetime | None = None,
                     base_delay_s: int = 60) -> dict:
    now = now or datetime.now(timezone.utc)
    sent, failed, retry = 0, 0, 0
    with db.read() as con:
        rows = con.execute("SELECT a.*, p.alert_email FROM alert a JOIN project p ON p.id=a.project_id "
                           "WHERE a.delivery_status='pending' ORDER BY a.created_at").fetchall()
    for r in rows:
        if r["next_attempt_at"] and parse_ts(r["next_attempt_at"]) > now:
            continue
        payload = json.loads(r["payload_json"])
        subject, body = render_email(payload)
        try:
            sender.send(r["alert_email"], subject, body, {"X-NodeTrust-Alert": r["id"],
                                                          "X-NodeTrust-Dedup": r["dedup_key"][:16]})
            status, err, nxt = "sent", None, None
            sent += 1
        except Exception as e:  # noqa: BLE001 - any delivery failure is retried
            attempts = r["attempts"] + 1
            err = redact(f"{type(e).__name__}: {e}")[:300]
            if attempts >= max_attempts:
                status, nxt = "failed", None
                failed += 1
            else:
                status = "pending"
                nxt = (now + timedelta(seconds=base_delay_s * 2 ** (attempts - 1))).isoformat(timespec="seconds") \
                    .replace("+00:00", "Z")
                retry += 1
            log(_log, logging.WARNING, "alert.delivery_failed", alert_id=r["id"], attempts=attempts, error=err)
        with db.transaction() as con:
            con.execute("UPDATE alert SET delivery_status=?, attempts=attempts+1, last_error=?, next_attempt_at=?, "
                        "updated_at=? WHERE id=?", (status, err, nxt, utcnow(), r["id"]))
            db.bump(con, f"alerts_{status}")
            db.audit(con, actor=f"system:{sender.name}", action=f"alert.delivery.{status}", project_id=r["project_id"],
                     target=r["id"], correlation_id=r["id"])
    return {"sent": sent, "failed": failed, "retry_later": retry}


def triage(con: sqlite3.Connection, *, project_id: str, alert_id: str, decision: str, actor: str, note: str) -> dict:
    if decision not in ("confirm", "reject"):
        raise ValueError("decision must be 'confirm' or 'reject'")
    if not note or len(note.strip()) < 5:
        raise ValueError("a triage note is required")
    row = con.execute("SELECT * FROM alert WHERE id=? AND project_id=?", (alert_id, project_id)).fetchone()
    if row is None:
        raise KeyError(alert_id)
    new = "confirmed" if decision == "confirm" else "rejected"
    con.execute("UPDATE alert SET triage_status=?, updated_at=? WHERE id=?", (new, utcnow(), alert_id))
    return {"alert_id": alert_id, "triage_status": new, "previous": row["triage_status"], "note": note.strip()[:1000]}


def list_alerts(con: sqlite3.Connection, project_id: str, limit: int = 100) -> list[dict]:
    out = []
    for r in con.execute("SELECT * FROM alert WHERE project_id=? ORDER BY created_at DESC LIMIT ?", (project_id, limit)):
        d = dict(r)
        d["payload"] = json.loads(d.pop("payload_json"))
        d.pop("dedup_key", None)
        out.append(d)
    return out
