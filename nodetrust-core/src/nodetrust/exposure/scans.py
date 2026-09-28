"""Scan storage (NT-018 persistence side).

A scan is identified by (project, commit, SBOM hash). Submitting the same SBOM
for the same commit again returns the existing scan: no duplicate drift,
alerts or verdict rows (NT-020 idempotency).

Unknown npm packages (exact version, but package not in the graph yet) are
queued for a targeted fetch and reported as "not in graph", never as safe.
Scan input is untrusted, so targeted fetches are bounded (FetchBudget): a cap per
scan, a global ceiling on pending SBOM jobs, a cooldown per package, and a lower
queue priority than the change feed. Invalid npm names never reach the queue.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from nodetrust.contracts import DataQuality
from nodetrust.registry.feed import PRIORITY_SBOM, enqueue_fetch
from nodetrust.sbom.cyclonedx import NormalizedSbom
from nodetrust.storage import dumps, new_id, utcnow


@dataclass
class ScanView:
    id: str
    project_id: str
    commit_sha: str
    branch: str
    run_id: str | None
    received_at: str
    sbom_sha256: str
    root_ref: str
    quality: DataQuality
    coverage: dict
    components: dict[str, dict] = field(default_factory=dict)  # ref -> row dict
    edges: set[tuple[str, str]] = field(default_factory=set)

    def label(self, ref: str) -> str:
        if ref == self.root_ref:
            return "(project root)"
        c = self.components.get(ref)
        if not c:
            return ref
        return f"{c['name']}@{c['version']}" if c["version"] else c["name"]

    def npm_versions(self) -> dict[str, tuple[str, str | None]]:
        return {r: (c["name"], c["version"]) for r, c in self.components.items() if c["ecosystem"] == "npm"}

    def identity(self) -> dict:
        return {"scan_id": self.id, "commit": self.commit_sha, "branch": self.branch, "run_id": self.run_id,
                "received_at": self.received_at, "sbom_sha256": self.sbom_sha256}


@dataclass(frozen=True)
class FetchBudget:
    """Limits on fetches that untrusted scan input can trigger (NT-041-style hardening)."""

    per_scan: int = 200            # distinct new package names queued by one scan
    max_pending: int = 5000        # ceiling on pending SBOM-triggered jobs across all projects
    cooldown_hours: float = 24.0   # do not re-fetch a package fetched this recently


def _queue_unknown(con: sqlite3.Connection, project_id: str, names: list[str], budget: FetchBudget) -> dict:
    pending = con.execute("SELECT COUNT(*) FROM fetch_job WHERE status='pending' AND priority=?",
                          (PRIORITY_SBOM,)).fetchone()[0]
    queued, skipped, already = 0, 0, 0
    for name in names:
        row = con.execute("SELECT status FROM fetch_job WHERE ecosystem='npm' AND name=?", (name,)).fetchone()
        if row is not None and row["status"] == "pending":
            already += 1  # already waiting: costs no budget
            continue
        if queued >= budget.per_scan or pending + queued >= budget.max_pending:
            skipped += 1
            continue
        if enqueue_fetch(con, name, f"sbom:{project_id}", priority=PRIORITY_SBOM,
                         cooldown_hours=budget.cooldown_hours):
            queued += 1
    return {"queued_for_fetch": queued, "already_queued": already, "not_queued": skipped}


def store_scan(con: sqlite3.Connection, *, project_id: str, sbom: NormalizedSbom, commit_sha: str, branch: str,
               run_id: str | None, budget: FetchBudget = FetchBudget()) -> tuple[str, bool]:
    existing = con.execute("SELECT id FROM scan WHERE project_id=? AND commit_sha=? AND sbom_sha256=?",
                           (project_id, commit_sha, sbom.sha256)).fetchone()
    if existing:
        return existing["id"], False
    sid = new_id("scan")
    direct = sbom.direct_refs()
    cov = sbom.coverage()
    # which exact npm packages are unknown to the graph?
    not_in_graph, unknown_names = [], []
    for c in sbom.npm():
        if c.status != "exact":
            continue
        known = con.execute("SELECT 1 FROM pkg_version WHERE ecosystem='npm' AND name=? AND version=?",
                            (c.name, c.version)).fetchone()
        if not known:
            not_in_graph.append(f"{c.name}@{c.version}")
            if c.name not in unknown_names:
                unknown_names.append(c.name)
    cov["not_in_graph"] = len(not_in_graph)
    cov["not_in_graph_sample"] = sorted(not_in_graph)[:50]
    cov.update(_queue_unknown(con, project_id, sorted(unknown_names), budget))
    cov["warnings"] = sbom.warnings[:50]
    con.execute(
        "INSERT INTO scan(id, project_id, commit_sha, branch, run_id, sbom_sha256, received_at, root_ref, "
        "component_count, quality, coverage_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (sid, project_id, commit_sha, branch, run_id, sbom.sha256, utcnow(), sbom.root_ref, len(sbom.components),
         sbom.quality().value, dumps(cov)))
    for c in sbom.components.values():
        con.execute("INSERT INTO scan_component(scan_id, ref, purl, ecosystem, name, version, status, scope, is_direct) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (sid, c.ref, c.purl, c.ecosystem, c.name, c.version, c.status, c.scope, int(c.ref in direct)))
    for s, d in sbom.edges:
        con.execute("INSERT INTO scan_edge(scan_id, src_ref, dst_ref) VALUES (?,?,?)", (sid, s, d))
    return sid, True


def load_scan(con: sqlite3.Connection, scan_id: str, project_id: str | None = None) -> ScanView | None:
    q, args = "SELECT * FROM scan WHERE id=?", [scan_id]
    if project_id is not None:
        q += " AND project_id=?"
        args.append(project_id)
    s = con.execute(q, args).fetchone()
    if not s:
        return None
    view = ScanView(id=s["id"], project_id=s["project_id"], commit_sha=s["commit_sha"], branch=s["branch"],
                    run_id=s["run_id"], received_at=s["received_at"], sbom_sha256=s["sbom_sha256"],
                    root_ref=s["root_ref"], quality=DataQuality(s["quality"]),
                    coverage=json.loads(s["coverage_json"]))
    for c in con.execute("SELECT * FROM scan_component WHERE scan_id=?", (scan_id,)):
        view.components[c["ref"]] = dict(c)
    view.edges = {(e["src_ref"], e["dst_ref"]) for e in con.execute(
        "SELECT src_ref, dst_ref FROM scan_edge WHERE scan_id=?", (scan_id,))}
    return view


def latest_scans(con: sqlite3.Connection, project_id: str, limit: int = 20) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT s.id, s.commit_sha, s.branch, s.run_id, s.received_at, s.component_count, s.quality, "
        "(SELECT decision FROM verdict v WHERE v.scan_id=s.id ORDER BY v.created_at DESC LIMIT 1) AS decision "
        "FROM scan s WHERE s.project_id=? ORDER BY s.received_at DESC, s.rowid DESC LIMIT ?", (project_id, limit))]
