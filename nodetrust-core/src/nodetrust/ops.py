"""Operational helpers: backup/restore with checksum, retention purge (NT-042).

Backup uses SQLite's online backup API, so it is consistent while the API runs.
A `.sha256` file is written next to the backup; restore refuses a file whose
checksum or integrity check fails, and keeps the previous database aside.

Retention only touches operational data (finished fetch jobs, delivered outbox
files). Scans, verdicts, alerts and the audit log are kept until the team agrees
a retention period for them (NT-042 acceptance: "retention disepakati").
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def backup(db_path: Path, out: Path) -> dict:
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise FileExistsError(f"{out} already exists; refusing to overwrite a backup")
    src = sqlite3.connect(str(db_path))
    dst = sqlite3.connect(str(out))
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    digest = _sha256(out)
    Path(str(out) + ".sha256").write_text(f"{digest}  {out.name}\n", encoding="utf-8")
    return {"backup": str(out), "sha256": digest, "bytes": out.stat().st_size}


def verify_backup(path: Path) -> dict:
    side = Path(str(path) + ".sha256")
    if not side.exists():
        raise ValueError(f"missing checksum file {side.name}")
    expected = side.read_text(encoding="utf-8").split()[0]
    actual = _sha256(path)
    if expected != actual:
        raise ValueError("checksum mismatch: backup is corrupted or was modified")
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        res = con.execute("PRAGMA integrity_check").fetchone()[0]
        rev = con.execute("SELECT value FROM meta WHERE key='schema_revision'").fetchone()
    finally:
        con.close()
    if res != "ok":
        raise ValueError(f"integrity_check failed: {res}")
    return {"sha256": actual, "integrity": res, "schema_revision": rev[0] if rev else None}


def restore(backup_path: Path, db_path: Path) -> dict:
    """Restore into db_path. The API and worker must be stopped first."""
    info = verify_backup(backup_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    kept = None
    if db_path.exists():
        kept = db_path.with_name(f"{db_path.name}.pre-restore-{datetime.now().strftime('%Y%m%d%H%M%S')}")
        shutil.move(str(db_path), str(kept))
        for ext in ("-wal", "-shm"):
            side = Path(str(db_path) + ext)
            if side.exists():
                shutil.move(str(side), str(kept) + ext)
    shutil.copyfile(backup_path, db_path)
    return {**info, "restored_to": str(db_path), "previous_kept_at": str(kept) if kept else None}


def purge(con: sqlite3.Connection, *, days: int, outbox: Path | None = None) -> dict:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds").replace("+00:00", "Z")
    jobs = con.execute("DELETE FROM fetch_job WHERE status IN ('done','failed') AND updated_at < ?", (cutoff,)).rowcount
    files = 0
    if outbox and outbox.exists():
        limit = (datetime.now() - timedelta(days=days)).timestamp()
        for p in outbox.glob("*.eml"):
            if p.stat().st_mtime < limit:
                os.remove(p)
                files += 1
    return {"cutoff": cutoff, "fetch_jobs_deleted": jobs, "outbox_files_deleted": files}
