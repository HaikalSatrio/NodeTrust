"""Dependency drift per push (NT-020).

Baseline = the most recent earlier scan of the same project and branch. Changes
are computed on exact npm package versions, keyed by package name (a package can
appear in several versions in one tree):
  added:   name not present in the baseline;
  removed: name no longer present;
  changed: name in both, different version set.
Drift is stored once per scan; resubmitting a scan does not recompute it.
"""

from __future__ import annotations

import json
import sqlite3

from nodetrust.exposure.scans import ScanView
from nodetrust.storage import dumps, utcnow


def _versions(con: sqlite3.Connection, scan_id: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for r in con.execute("SELECT name, version FROM scan_component WHERE scan_id=? AND ecosystem='npm' "
                         "AND status='exact'", (scan_id,)):
        out.setdefault(r["name"], set()).add(r["version"])
    return out


def compute_drift(con: sqlite3.Connection, scan: ScanView) -> dict:
    existing = con.execute("SELECT * FROM drift WHERE scan_id=?", (scan.id,)).fetchone()
    if existing:
        return _row(con, existing)
    base = con.execute(
        "SELECT id FROM scan WHERE project_id=? AND branch=? AND id != ? AND "
        "(received_at < ? OR (received_at = ? AND rowid < (SELECT rowid FROM scan WHERE id=?))) "
        "ORDER BY received_at DESC, rowid DESC LIMIT 1",
        (scan.project_id, scan.branch, scan.id, scan.received_at, scan.received_at, scan.id)).fetchone()
    cur = _versions(con, scan.id)
    added, removed, changed = [], [], []
    if base:
        old = _versions(con, base["id"])
        for n in sorted(set(cur) - set(old)):
            added.append({"name": n, "versions": sorted(cur[n])})
        for n in sorted(set(old) - set(cur)):
            removed.append({"name": n, "versions": sorted(old[n])})
        for n in sorted(set(cur) & set(old)):
            if cur[n] != old[n]:
                changed.append({"name": n, "from": sorted(old[n]), "to": sorted(cur[n])})
    con.execute("INSERT INTO drift(scan_id, project_id, base_scan_id, added_json, removed_json, changed_json, "
                "created_at) VALUES (?,?,?,?,?,?,?)",
                (scan.id, scan.project_id, base["id"] if base else None, dumps(added), dumps(removed), dumps(changed),
                 utcnow()))
    return _row(con, con.execute("SELECT * FROM drift WHERE scan_id=?", (scan.id,)).fetchone())


def _row(con: sqlite3.Connection, r: sqlite3.Row) -> dict:
    base = None
    if r["base_scan_id"]:
        b = con.execute("SELECT id, commit_sha, branch, received_at FROM scan WHERE id=?", (r["base_scan_id"],)).fetchone()
        base = dict(b) if b else {"id": r["base_scan_id"]}
    cur = con.execute("SELECT id, commit_sha, branch, received_at FROM scan WHERE id=?", (r["scan_id"],)).fetchone()
    return {"scan": dict(cur), "baseline": base, "added": json.loads(r["added_json"]),
            "removed": json.loads(r["removed_json"]), "changed": json.loads(r["changed_json"]),
            "first_scan": base is None}
