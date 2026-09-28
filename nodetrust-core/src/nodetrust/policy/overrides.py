"""Overrides and approvals (NT-022 / NT-025, rules from NT-001 D04 + D06).

Override (D06): only an authenticated project admin, reason required, bound to
project + scan (commit) + policy version + evidence fingerprint, valid for one
CI run and at most `override_max_hours` (<= 24h). A different commit, a new
policy version, or any change in the evidence invalidates it. Overrides can be
revoked; nothing is deleted and findings stay in the verdict.

Approval (D04): created when a build is held for a verified CRITICAL with a
large/UNKNOWN radius. One approval per (project, incident, scan). Only a project
admin can decide 'block' or 'allow'; CI keys cannot.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone

from nodetrust.storage import new_id, parse_ts, utcnow


class OverrideError(ValueError):
    pass


def evidence_fingerprint(sbom_sha256: str, findings: list[dict]) -> str:
    parts = [sbom_sha256] + sorted(f"{f['incident_id']}:{f['evidence_version']}" for f in findings)
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def create_override(con: sqlite3.Connection, *, project_id: str, scan_id: str, reason: str, actor: str,
                    hours: float, max_hours: float, incident_id: str | None = None) -> dict:
    if not reason or len(reason.strip()) < 10:
        raise OverrideError("a reason of at least 10 characters is required")
    if hours <= 0 or hours > max_hours:
        raise OverrideError(f"hours must be in (0, {max_hours}]")
    v = con.execute("SELECT commit_sha, policy_version, body_json FROM verdict WHERE project_id=? AND scan_id=? "
                    "ORDER BY created_at DESC, rowid DESC LIMIT 1", (project_id, scan_id)).fetchone()
    if v is None:
        raise OverrideError("no verdict exists for this scan; override must refer to an evaluated scan")
    body = json.loads(v["body_json"])
    now = datetime.now(timezone.utc)
    oid = new_id("ovr")
    con.execute(
        "INSERT INTO override(id, project_id, commit_sha, policy_version, incident_id, scan_id, reason, created_by, "
        "created_at, expires_at, evidence_fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (oid, project_id, v["commit_sha"], v["policy_version"], incident_id, scan_id, reason.strip()[:1000], actor,
         utcnow(), (now + timedelta(hours=hours)).isoformat(timespec="seconds").replace("+00:00", "Z"),
         body["evidence_fingerprint"]))
    return dict(con.execute("SELECT * FROM override WHERE id=?", (oid,)).fetchone())


def revoke_override(con: sqlite3.Connection, project_id: str, override_id: str) -> bool:
    cur = con.execute("UPDATE override SET revoked_at=? WHERE id=? AND project_id=? AND revoked_at IS NULL",
                      (utcnow(), override_id, project_id))
    return cur.rowcount == 1


def find_override(con: sqlite3.Connection, *, project_id: str, commit_sha: str, policy_version: int,
                  fingerprint: str, run_id: str | None, now: datetime | None = None) -> tuple[dict | None, list[str]]:
    """Return (valid override or None, reasons why candidates were rejected)."""
    now = now or datetime.now(timezone.utc)
    rejected: list[str] = []
    rows = con.execute("SELECT * FROM override WHERE project_id=? ORDER BY created_at DESC", (project_id,)).fetchall()
    for o in rows:
        why = None
        if o["revoked_at"]:
            why = "revoked"
        elif parse_ts(o["expires_at"]) <= now:
            why = "expired"
        elif o["commit_sha"] != commit_sha:
            why = "different commit"
        elif o["policy_version"] != policy_version:
            why = "policy version changed"
        elif o["evidence_fingerprint"] != fingerprint:
            why = "evidence changed since the override was granted"
        elif o["consumed_at"] and (run_id is None or o["consumed_run_id"] != run_id):
            why = "already used by another run"
        if why:
            # only report candidates that were plausibly meant for this build
            if o["commit_sha"] == commit_sha or why in ("expired", "revoked"):
                rejected.append(f"{o['id']}: {why}")
            continue
        return dict(o), rejected
    return None, rejected


def consume_override(con: sqlite3.Connection, override_id: str, run_id: str | None) -> None:
    con.execute("UPDATE override SET consumed_at=COALESCE(consumed_at, ?), consumed_run_id=COALESCE(consumed_run_id, ?) "
                "WHERE id=?", (utcnow(), run_id or "no-run-id", override_id))


# ---------------------------------------------------------------- approvals

def approvals_for_scan(con: sqlite3.Connection, project_id: str, scan_id: str) -> dict[str, str]:
    return {r["incident_id"]: r["status"] for r in con.execute(
        "SELECT incident_id, status FROM approval WHERE project_id=? AND scan_id=?", (project_id, scan_id))}


def request_approval(con: sqlite3.Connection, *, project_id: str, incident_id: str, scan_id: str, reason: str) -> str:
    row = con.execute("SELECT id FROM approval WHERE project_id=? AND incident_id=? AND scan_id=?",
                      (project_id, incident_id, scan_id)).fetchone()
    if row:
        return row["id"]
    aid = new_id("apr")
    con.execute("INSERT INTO approval(id, project_id, incident_id, scan_id, reason, status, requested_at) "
                "VALUES (?,?,?,?,?,'pending',?)", (aid, project_id, incident_id, scan_id, reason[:500], utcnow()))
    return aid


def decide_approval(con: sqlite3.Connection, *, project_id: str, approval_id: str, decision: str, actor: str,
                    note: str) -> dict:
    if decision not in ("block", "allow"):
        raise ValueError("decision must be 'block' or 'allow'")
    if not note or len(note.strip()) < 5:
        raise ValueError("a decision note is required")
    row = con.execute("SELECT * FROM approval WHERE id=? AND project_id=?", (approval_id, project_id)).fetchone()
    if row is None:
        raise KeyError(approval_id)
    if row["status"] != "pending":
        raise ValueError(f"approval already decided: {row['status']}")
    con.execute("UPDATE approval SET status=?, decided_by=?, decided_at=?, decision_note=? WHERE id=?",
                (decision, actor, utcnow(), note.strip()[:1000], approval_id))
    return dict(con.execute("SELECT * FROM approval WHERE id=?", (approval_id,)).fetchone())
