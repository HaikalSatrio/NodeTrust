"""Client overlay and baseline report (NT-019).

Maps a project's scan onto the package graph and reports: direct vs transitive
dependency counts, depth, choke points (dominators from the root), heuristic
risk of each component version (when the graph has scored it), and resolution
coverage. Packages the graph does not know are listed as "not assessed", and the
report never counts them as safe.
"""

from __future__ import annotations

import sqlite3
from collections import deque

from nodetrust.exposure.scans import ScanView
from nodetrust.graph.centrality import choke_points
from nodetrust.graph.store import snapshot_id
from nodetrust.intel.osv import advisories_for
from nodetrust.risk.scoring import latest_score
from nodetrust.storage import utcnow


def _depths(scan: ScanView) -> dict[str, int]:
    adj: dict[str, list[str]] = {}
    for s, d in scan.edges:
        adj.setdefault(s, []).append(d)
    depth = {scan.root_ref: 0}
    q = deque([scan.root_ref])
    while q:
        n = q.popleft()
        for m in adj.get(n, []):
            if m not in depth:
                depth[m] = depth[n] + 1
                q.append(m)
    return depth


def baseline_report(con: sqlite3.Connection, scan: ScanView) -> dict:
    npm = {r: c for r, c in scan.components.items() if c["ecosystem"] == "npm"}
    depths = _depths(scan)
    direct = {r for r, c in npm.items() if c["is_direct"]}
    reachable = {r for r in npm if r in depths}
    risky, not_assessed, in_graph, vulns = [], [], 0, []
    for r, c in sorted(npm.items(), key=lambda kv: (kv[1]["name"], kv[1]["version"] or "")):
        if c["status"] != "exact":
            not_assessed.append({"package": c["name"], "version": c["version"], "why": "no exact version"})
            continue
        known = con.execute("SELECT 1 FROM pkg_version WHERE ecosystem='npm' AND name=? AND version=?",
                            (c["name"], c["version"])).fetchone()
        if not known:
            not_assessed.append({"package": c["name"], "version": c["version"],
                                 "why": "not in graph yet (queued for targeted fetch)"})
        else:
            in_graph += 1
            s = latest_score(con, c["name"], c["version"])
            if s and s["tier"] != "NORMAL":
                risky.append({"package": f"{c['name']}@{c['version']}", "score": s["score"], "tier": s["tier"],
                              "rules_version": s["rules_version"], "score_kind": "heuristic",
                              "reasons": [x["rule"] for x in s["reasons"] if x["weight"]]})
        for adv in advisories_for(con, c["name"], c["version"]):
            vulns.append({"package": f"{c['name']}@{c['version']}", "ids": adv["ids"], "kind": adv["kind"],
                          "summary": adv["summary"], "is_evidence_of_compromise": False})
    exact_count = sum(1 for c in npm.values() if c["status"] == "exact")
    labels = {r: scan.label(r) for r in scan.components}
    return {
        "scan": scan.identity(),
        "generated_at": utcnow(),
        "graph_snapshot": snapshot_id(con),
        "data_quality": scan.quality.value,
        "counts": {
            "npm_components": len(npm),
            "direct": len(direct),
            "transitive": len(reachable - direct),
            "unreachable_from_root": len(set(npm) - reachable) if scan.edges else None,
            "max_depth": max((depths[r] for r in reachable), default=0),
            "out_of_scope_components": scan.coverage.get("out_of_scope", 0),
        },
        "coverage": {
            "exact_versions": exact_count,
            "in_graph": in_graph,
            "not_assessed": len(not_assessed),
            "resolution_ratio": round(in_graph / len(npm), 4) if npm else None,
            "note": "Packages not assessed are unknown, not safe.",
        },
        "choke_points": choke_points(scan.root_ref, scan.edges, labels) if scan.edges else [],
        "risk": sorted(risky, key=lambda x: -x["score"]),
        "vulnerabilities": vulns,
        "not_assessed": not_assessed[:200],
    }
