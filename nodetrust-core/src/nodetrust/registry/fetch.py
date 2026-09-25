"""Incremental packument fetch + graph write (NT-007, feeding NT-008/009/010).

Only packages with a pending job are fetched: jobs come from the change feed
(NT-006) or from targeted requests (unknown packages seen in an SBOM, NT-018).
A job is marked done in the same transaction that writes the graph, so a failed
write leaves the job pending and it is simply processed again.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from urllib.parse import quote

from nodetrust.contracts import ECOSYSTEM_NPM
from nodetrust.graph.store import upsert_packument
from nodetrust.incidents import upsert_crawler_signal
from nodetrust.obs import correlation, get_logger, log
from nodetrust.registry.normalize import InvalidPackument, normalize_packument
from nodetrust.registry.transport import (NetworkDisabled, RateLimiter, ResponseTooLarge, Transport, TransportError,
                                          fetch_with_retry)
from nodetrust.risk.diff import diff_version
from nodetrust.risk.scoring import score_and_store
from nodetrust.storage import Database, utcnow

_log = get_logger("fetch")


def packument_url(registry: str, name: str) -> str:
    # scoped names keep '@' and encode the slash: @scope%2fname
    return f"{registry.rstrip('/')}/{quote(name, safe='@')}"


@dataclass
class FetchReport:
    processed: int = 0
    new_versions: int = 0
    scored: int = 0
    signals: int = 0
    failed: list[str] = field(default_factory=list)
    retry_later: list[str] = field(default_factory=list)
    not_found: list[str] = field(default_factory=list)
    invalid_items: list[str] = field(default_factory=list)


class Fetcher:
    def __init__(self, db: Database, transport: Transport, registry_url: str, *, timeout: float = 20.0,
                 max_bytes: int = 20 * 1024 * 1024, limiter: RateLimiter | None = None, max_attempts: int = 5,
                 sleep=None):
        self.db, self.transport, self.registry = db, transport, registry_url
        self.timeout, self.max_bytes, self.limiter = timeout, max_bytes, limiter
        self.max_attempts = max_attempts
        self._sleep = sleep

    def _mark(self, name: str, status: str, error: str | None = None, bump_attempt: bool = False) -> None:
        with self.db.transaction() as con:
            con.execute("UPDATE fetch_job SET status=?, last_error=?, updated_at=?, "
                        "attempts = attempts + ? WHERE ecosystem=? AND name=?",
                        (status, error, utcnow(), int(bump_attempt), ECOSYSTEM_NPM, name))

    def process_pending(self, limit: int = 100) -> FetchReport:
        with self.db.read() as con:
            jobs = con.execute("SELECT name, reason, seq, attempts FROM fetch_job WHERE ecosystem=? AND "
                               "status='pending' ORDER BY priority DESC, requested_at LIMIT ?", (ECOSYSTEM_NPM, limit)).fetchall()
        rep = FetchReport()
        for job in jobs:
            with correlation(f"fetch:{job['name']}:{job['seq'] or '-'}"):
                self._process(job["name"], job["attempts"], rep)
        self.db.set_sync("registry:fetch", ok=not rep.failed,
                         error=f"{len(rep.failed)} failed" if rep.failed else None,
                         detail={"processed": rep.processed, "new_versions": rep.new_versions})
        return rep

    def _process(self, name: str, attempts: int, rep: FetchReport) -> None:
        url = packument_url(self.registry, name)
        kwargs = {"sleep": self._sleep} if self._sleep else {}
        try:
            resp = fetch_with_retry(self.transport, "GET", url, timeout=self.timeout, max_bytes=self.max_bytes,
                                    limiter=self.limiter, headers={"accept": "application/json"}, **kwargs)
        except NetworkDisabled:
            raise
        except ResponseTooLarge as e:
            self._mark(name, "failed", f"too large: {e}")
            rep.failed.append(name)
            return
        except TransportError as e:
            status = "failed" if attempts + 1 >= self.max_attempts else "pending"
            self._mark(name, status, str(e), bump_attempt=True)
            (rep.failed if status == "failed" else rep.retry_later).append(name)
            log(_log, logging.WARNING, "fetch.transport_error", package=name, error=str(e), attempts=attempts + 1)
            return
        if resp.status == 404:
            # Unpublished or never existed: keep whatever history we have.
            self._mark(name, "done", "not found (404)")
            rep.not_found.append(name)
            return
        if resp.status != 200:
            self._mark(name, "failed", f"HTTP {resp.status}")
            rep.failed.append(name)
            return
        try:
            rec = normalize_packument(json.loads(resp.body), expected_name=name)
        except (ValueError, InvalidPackument) as e:  # json errors are ValueError too
            self._mark(name, "failed", f"invalid packument: {e}")
            rep.failed.append(name)
            log(_log, logging.WARNING, "fetch.invalid_packument", package=name, error=str(e))
            return
        rep.invalid_items.extend(rec.errors)

        with self.db.transaction() as con:
            res = upsert_packument(con, rec)
            baseline_ingest = res.maintainers_before is None  # first time we see this package
            changed = {v for v, _, _ in res.integrity_changes}
            for version in sorted(set(res.new_versions) | changed):
                delta = diff_version(con, name, version)
                score = score_and_store(con, delta)
                rep.scored += 1
                # A first ingest scores history but does not raise signals for it:
                # old releases are not news. Integrity changes always count.
                if (not baseline_ingest or version in changed) and upsert_crawler_signal(con, score):
                    rep.signals += 1
            con.execute("UPDATE fetch_job SET status='done', last_error=NULL, updated_at=? "
                        "WHERE ecosystem=? AND name=?", (utcnow(), ECOSYSTEM_NPM, name))
            self.db.bump(con, "packuments_fetched")
            self.db.bump(con, "versions_ingested", len(res.new_versions))
            if res.integrity_changes:
                self.db.bump(con, "same_version_integrity_changes", len(res.integrity_changes))
        rep.processed += 1
        rep.new_versions += len(res.new_versions)
        log(_log, logging.INFO, "fetch.done", package=name, new_versions=len(res.new_versions),
            integrity_changes=len(res.integrity_changes), invalid_items=len(rec.errors))
