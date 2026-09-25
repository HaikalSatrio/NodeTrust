"""npm change-feed listener with durable checkpoint (NT-006).

Protocol (CouchDB-style `_changes`, as exposed by npm's replicate service):
    GET <changes_url>?since=<seq>&limit=<n>
    -> {"results": [{"seq": .., "id": "<package>", "deleted": bool?}, ...], "last_seq": ..}

The exact endpoint and response shape must be verified against npm's current
documentation before live use; that check needs network access and is still open
(see docs/audit/NT-040-audit.md). The parser accepts integer or string sequence
ids and tolerates missing `last_seq`.

Delivery guarantee: for each page, fetch jobs for the changed packages and the
new checkpoint are written in ONE transaction. A crash before commit replays the
page (jobs are idempotent per package); a crash after commit loses nothing
because the jobs are already durable. The checkpoint is therefore never ahead of
work that has been accepted.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import urlencode

from nodetrust.contracts import ECOSYSTEM_NPM, valid_npm_name
from nodetrust.obs import get_logger, log
from nodetrust.registry.transport import NetworkDisabled, Transport, TransportError, fetch_with_retry
from nodetrust.storage import Database, utcnow

_log = get_logger("feed")


class FeedFormatError(ValueError):
    pass


@dataclass
class PollResult:
    since: str
    next_seq: str
    changes: int = 0
    enqueued: int = 0
    skipped_unwatched: int = 0
    pending_upstream: int | None = None
    errors: list[str] = field(default_factory=list)


def get_checkpoint(db: Database, feed: str) -> str | None:
    with db.read() as con:
        row = con.execute("SELECT seq FROM feed_checkpoint WHERE feed=?", (feed,)).fetchone()
    return row["seq"] if row else None


PRIORITY_FEED = 10  # change feed, watchlist, operator requests
PRIORITY_SBOM = 0   # targeted fetches caused by (untrusted) scan input


def enqueue_fetch(con, name: str, reason: str, seq: str | None = None, *, priority: int = PRIORITY_FEED,
                  cooldown_hours: float | None = None) -> bool:
    """Queue (or re-queue) a fetch. Returns True if a job was created or updated.

    With `cooldown_hours`, a job that finished (done/failed) more recently than that
    is left alone, so the same unknown package is not re-fetched on every scan."""
    now = utcnow()
    since = None
    if cooldown_hours is not None:
        since = (datetime.now(timezone.utc) - timedelta(hours=cooldown_hours)).isoformat(timespec="seconds") \
            .replace("+00:00", "Z")
    cur = con.execute(
        "INSERT INTO fetch_job(ecosystem, name, reason, seq, status, attempts, requested_at, updated_at, priority) "
        "VALUES (?,?,?,?, 'pending', 0, ?, ?, ?) ON CONFLICT(ecosystem, name) DO UPDATE SET "
        "status='pending', "
        "reason=CASE WHEN excluded.priority >= fetch_job.priority THEN excluded.reason ELSE fetch_job.reason END, "
        "priority=MAX(fetch_job.priority, excluded.priority), "
        "seq=COALESCE(excluded.seq, fetch_job.seq), "
        "attempts=CASE WHEN fetch_job.status='pending' THEN fetch_job.attempts ELSE 0 END, "
        "updated_at=excluded.updated_at "
        "WHERE ? IS NULL OR fetch_job.status='pending' OR fetch_job.updated_at < ?",
        (ECOSYSTEM_NPM, name, reason, seq, now, now, priority, since, since))
    return cur.rowcount > 0


def parse_changes_page(body: bytes) -> tuple[list[dict], str | None, int | None]:
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError) as e:
        raise FeedFormatError(f"changes page is not JSON: {e}") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        raise FeedFormatError("changes page has no 'results' list")
    out = []
    for r in doc["results"]:
        if not isinstance(r, dict) or "seq" not in r or not isinstance(r.get("id"), str):
            raise FeedFormatError(f"malformed change row: {str(r)[:120]}")
        out.append({"seq": str(r["seq"]), "id": r["id"], "deleted": bool(r.get("deleted"))})
    last = doc.get("last_seq")
    pending = doc.get("pending") if isinstance(doc.get("pending"), int) else None
    return out, (str(last) if last is not None else None), pending


class ChangesFeed:
    def __init__(self, db: Database, transport: Transport, changes_url: str, *, feed: str = "npm",
                 page_limit: int = 500, watch_all: bool = False, timeout: float = 30.0,
                 start_seq: str = "now", sleep: Callable[[float], None] = time.sleep):
        self.db, self.transport, self.url = db, transport, changes_url
        self.feed, self.page_limit, self.watch_all = feed, page_limit, watch_all
        self.timeout, self.start_seq, self.sleep = timeout, start_seq, sleep

    def _watched(self, con) -> set[str]:
        return {r["name"] for r in con.execute("SELECT name FROM watchlist WHERE ecosystem=?", (ECOSYSTEM_NPM,))}

    def poll_once(self) -> PollResult:
        since = get_checkpoint(self.db, self.feed) or self.start_seq
        url = f"{self.url}?{urlencode({'since': since, 'limit': self.page_limit})}"
        try:
            resp = fetch_with_retry(self.transport, "GET", url, timeout=self.timeout, max_bytes=50 * 1024 * 1024,
                                    sleep=self.sleep)
        except (TransportError, NetworkDisabled) as e:
            self.db.set_sync(f"feed:{self.feed}", ok=False, error=str(e))
            log(_log, logging.WARNING, "feed.poll_failed", feed=self.feed, since=since, error=str(e))
            raise
        if resp.status != 200:
            err = f"HTTP {resp.status} from changes feed"
            self.db.set_sync(f"feed:{self.feed}", ok=False, error=err)
            raise TransportError(err)
        try:
            rows, last_seq, pending = parse_changes_page(resp.body)
        except FeedFormatError as e:
            self.db.set_sync(f"feed:{self.feed}", ok=False, error=str(e))
            raise
        next_seq = last_seq or (rows[-1]["seq"] if rows else since)
        res = PollResult(since=since, next_seq=next_seq, changes=len(rows), pending_upstream=pending)

        with self.db.transaction() as con:
            watched = self._watched(con)
            for r in rows:
                name = r["id"].lower()
                if name.startswith("_design/") or not valid_npm_name(name):
                    res.errors.append(f"ignored id {r['id']!r}")
                    continue
                if not self.watch_all and name not in watched:
                    res.skipped_unwatched += 1
                    continue
                enqueue_fetch(con, name, "feed:deleted" if r["deleted"] else "feed", r["seq"])
                res.enqueued += 1
            con.execute("INSERT INTO feed_checkpoint(feed, seq, updated_at) VALUES (?,?,?) "
                        "ON CONFLICT(feed) DO UPDATE SET seq=excluded.seq, updated_at=excluded.updated_at",
                        (self.feed, next_seq, utcnow()))
            self.db.bump(con, "feed_changes_seen", res.changes)
            self.db.bump(con, "feed_jobs_enqueued", res.enqueued)
        self.db.set_sync(f"feed:{self.feed}", ok=True,
                         detail={"seq": next_seq, "pending_upstream": pending, "changes": res.changes})
        log(_log, logging.INFO, "feed.page", feed=self.feed, since=since, next_seq=next_seq,
            changes=res.changes, enqueued=res.enqueued, pending_upstream=pending)
        return res

    def run(self, *, max_polls: int | None = None, idle_sleep: float = 5.0, max_backoff: float = 300.0) -> None:
        """Poll until max_polls; on failure back off exponentially and retry from
        the stored checkpoint (reconnect behaviour)."""
        polls, backoff = 0, idle_sleep
        while max_polls is None or polls < max_polls:
            polls += 1
            try:
                res = self.poll_once()
                backoff = idle_sleep
                if res.changes == 0:
                    self.sleep(idle_sleep)
            except NetworkDisabled:
                raise
            except (TransportError, FeedFormatError):
                self.sleep(backoff)
                backoff = min(max_backoff, backoff * 2)
