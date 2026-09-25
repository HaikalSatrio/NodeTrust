"""Incidents: the unit that exposure matching, policy and alerts work on.

An incident says "these versions of package P are suspect", with a heuristic
risk score (-> tier) and an evidence status. Sources:
- manual: curated by an operator (may be marked simulation for demos);
- crawler: heuristic signals from NT-009/010 (always starts UNVERIFIED);
- osv: an OSV *malicious-package report* (MAL-*) (starts UNVERIFIED).

Plain OSV vulnerability advisories are NOT incidents: a vulnerability is not a
compromise (NT-001 D04). They are reported separately.

Only a human with operator rights can set evidence to VERIFIED. Every evidence
change bumps evidence_version, which feeds alert de-duplication (D03) and
invalidates overrides (D06).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from nodetrust.contracts import ECOSYSTEM_NPM, EvidenceStatus, tier_for_score
from nodetrust.semver import SemverError, parse_version
from nodetrust.storage import dumps, new_id, utcnow

SIGNAL_MIN_SCORE = 41  # WATCH and above become crawler incidents


def affects(affected: dict, version: str) -> bool:
    """OSV-style affected check: explicit versions, or SEMVER ranges built from
    introduced / fixed / last_affected / limit events."""
    if version in (affected.get("versions") or []):
        return True
    try:
        v = parse_version(version)
    except SemverError:
        return False
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        if _in_range(v, rng.get("events") or []):
            return True
    return False


def _in_range(v, events: list[dict]) -> bool:
    # Evaluate the sorted event list per OSV spec: walk events in version order.
    def key(ev):
        (_, val), = ev.items()
        return (0, parse_version("0.0.0")) if val == "0" else (1, parse_version(val))

    try:
        evs = sorted((e for e in events if len(e) == 1), key=key)
    except SemverError:
        return False
    affected = False
    for ev in evs:
        (kind, val), = ev.items()
        bound = parse_version("0.0.0") if val == "0" else parse_version(val)
        if kind == "introduced":
            if v >= bound:
                affected = True
        elif kind == "fixed":
            if v >= bound:
                affected = False
        elif kind == "last_affected":
            if v > bound:
                affected = False
        elif kind == "limit":
            if v >= bound:
                affected = False
    return affected


def _row_to_dict(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["affected"] = json.loads(d.pop("affected_json"))
    d["is_simulation"] = bool(d["is_simulation"])
    d["tier"] = tier_for_score(d["risk_score"]).value
    return d


def get_incident(con: sqlite3.Connection, incident_id: str) -> dict | None:
    r = con.execute("SELECT * FROM incident WHERE id=?", (incident_id,)).fetchone()
    return _row_to_dict(r) if r else None


def list_incidents(con: sqlite3.Connection, *, name: str | None = None, include_rejected: bool = False) -> list[dict]:
    q, args = "SELECT * FROM incident WHERE 1=1", []
    if name:
        q += " AND ecosystem=? AND name=?"
        args += [ECOSYSTEM_NPM, name]
    if not include_rejected:
        q += " AND evidence_status != ?"
        args.append(EvidenceStatus.REJECTED.value)
    return [_row_to_dict(r) for r in con.execute(q + " ORDER BY created_at DESC", args)]


def create_incident(con: sqlite3.Connection, *, title: str, name: str, affected: dict, risk_score: int,
                    source: str = "manual", source_ref: str | None = None, is_simulation: bool = False,
                    evidence_status: EvidenceStatus = EvidenceStatus.UNVERIFIED, detected_at: str | None = None,
                    notes: str | None = None) -> dict:
    tier_for_score(risk_score)  # validates range/type
    if not (affected.get("versions") or affected.get("ranges")):
        raise ValueError("incident must list affected versions or ranges")
    now = utcnow()
    iid = new_id("inc")
    con.execute(
        "INSERT INTO incident(id, title, source, source_ref, ecosystem, name, affected_json, risk_score, "
        "evidence_status, evidence_version, is_simulation, detected_at, created_at, updated_at, notes) "
        "VALUES (?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)",
        (iid, title[:300], source, source_ref, ECOSYSTEM_NPM, name.lower(), dumps(affected), risk_score,
         evidence_status.value, int(is_simulation), detected_at or now, now, now, notes))
    return get_incident(con, iid)


def update_evidence(con: sqlite3.Connection, incident_id: str, *, status: EvidenceStatus | None = None,
                    risk_score: int | None = None, notes: str | None = None) -> dict:
    cur = get_incident(con, incident_id)
    if cur is None:
        raise KeyError(incident_id)
    fields: dict[str, Any] = {}
    if status is not None and status.value != cur["evidence_status"]:
        fields["evidence_status"] = status.value
    if risk_score is not None and risk_score != cur["risk_score"]:
        tier_for_score(risk_score)
        fields["risk_score"] = risk_score
    if notes is not None:
        fields["notes"] = notes
    if not fields:
        return cur
    bump = "evidence_status" in fields or "risk_score" in fields
    sets = ", ".join(f"{k}=?" for k in fields)
    con.execute(f"UPDATE incident SET {sets}, updated_at=?, evidence_version = evidence_version + ? WHERE id=?",
                (*fields.values(), utcnow(), int(bump), incident_id))
    return get_incident(con, incident_id)


def upsert_crawler_signal(con: sqlite3.Connection, score) -> bool:
    """Create/refresh an UNVERIFIED incident for a heuristic score >= WATCH.
    Returns True when an incident was created or its score changed."""
    ref = f"crawler:{score.name}@{score.version}:{score.rules_version}"
    row = con.execute("SELECT id, risk_score FROM incident WHERE source='crawler' AND source_ref=?", (ref,)).fetchone()
    if score.score < SIGNAL_MIN_SCORE:
        return False
    if row is None:
        rules = ", ".join(r["rule"] for r in score.reasons if r["weight"])
        create_incident(con, title=f"Heuristic signals on {score.name}@{score.version}: {rules}",
                        name=score.name, affected={"versions": [score.version]}, risk_score=score.score,
                        source="crawler", source_ref=ref,
                        notes="Automatically raised from metadata signals; unverified. Not evidence of compromise.")
        return True
    if row["risk_score"] != score.score:
        update_evidence(con, row["id"], risk_score=score.score)
        return True
    return False
