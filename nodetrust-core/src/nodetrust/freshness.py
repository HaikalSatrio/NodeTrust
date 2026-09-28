"""Data freshness (NT-001 D06).

A live assessment needs every required source (npm feed, OSV intel by default)
to have synced successfully within `stale_after_hours`. Otherwise the data is
STALE and the assessment is UNKNOWN. Snapshot instances (offline demo) are not
judged stale; instead every verdict carries an explicit "offline snapshot, not a
live assessment" label.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from nodetrust.storage import parse_ts


def freshness(con: sqlite3.Connection, *, required: list[str], stale_after_hours: float, snapshot_mode: bool,
              now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    sources = {}
    stale = False
    for src in required:
        row = con.execute("SELECT last_success_at, last_attempt_at, last_error FROM sync_status WHERE source=?",
                          (src,)).fetchone()
        last = parse_ts(row["last_success_at"]) if row else None
        age_h = round((now - last).total_seconds() / 3600, 2) if last else None
        ok = age_h is not None and age_h <= stale_after_hours
        sources[src] = {"last_success_at": row["last_success_at"] if row else None, "age_hours": age_h,
                        "status": "fresh" if ok else ("never_synced" if last is None else "stale"),
                        "last_error": row["last_error"] if row else None}
        stale = stale or not ok
    out = {"mode": "snapshot" if snapshot_mode else "live", "stale_after_hours": stale_after_hours,
           "sources": sources, "stale": bool(stale and not snapshot_mode)}
    if snapshot_mode:
        out["label"] = "Offline snapshot assessment - not a live assessment."
    return out
