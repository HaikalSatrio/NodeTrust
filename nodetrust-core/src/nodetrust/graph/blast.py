"""Blast radius.

Two different questions, kept apart on purpose:

1. `reverse_bfs`, on the public registry graph: which package versions declare
   a dependency spec that admits the seed version, directly or transitively.
   This is "could pull it in", not "does pull it in". Stand-in for NT-012
   (owner: Haikal): BFS with hop counts, one shortest path per dependent,
   cycle-safe, and explicit truncation when limits are hit.

2. `project_radius`, inside one client scan (exact versions from the SBOM):
   which components sit on a path from the project root to the seed. This is
   what D05 ("blast radius besar") is measured on.
"""

from __future__ import annotations

import sqlite3
from collections import deque
from dataclasses import dataclass, field

from nodetrust.contracts import ECOSYSTEM_NPM, PackageId
from nodetrust.graph.store import dependents_of


@dataclass
class BlastResult:
    seed: str
    dependents: list[dict] = field(default_factory=list)  # {package, hop, path: [keys seed->...->dependent]}
    truncated: bool = False
    truncation_reason: str | None = None
    max_hop: int = 0

    def by_hop(self) -> dict[int, int]:
        out: dict[int, int] = {}
        for d in self.dependents:
            out[d["hop"]] = out.get(d["hop"], 0) + 1
        return out

    def to_dict(self) -> dict:
        return {"seed": self.seed, "count": len(self.dependents), "by_hop": self.by_hop(),
                "truncated": self.truncated, "truncation_reason": self.truncation_reason,
                "dependents": self.dependents, "semantics": "declared-spec admits version (registry graph)"}


def reverse_bfs(con: sqlite3.Connection, name: str, version: str, *, max_nodes: int = 5000, max_depth: int = 25,
                ecosystem: str = ECOSYSTEM_NPM) -> BlastResult:
    seed = PackageId(ecosystem, name, version)
    res = BlastResult(seed.key())
    parent: dict[PackageId, PackageId | None] = {seed: None}
    hop: dict[PackageId, int] = {seed: 0}
    q = deque([seed])
    while q:
        cur = q.popleft()
        if hop[cur] >= max_depth:
            if dependents_of(con, cur.name, cur.version, ecosystem):
                res.truncated, res.truncation_reason = True, f"max_depth={max_depth}"
            continue
        for dep, _spec, _kind in dependents_of(con, cur.name, cur.version, ecosystem):
            if dep in parent:
                continue  # cycle or already reached by a shorter path
            if len(parent) - 1 >= max_nodes:
                res.truncated, res.truncation_reason = True, f"max_nodes={max_nodes}"
                q.clear()
                break
            parent[dep] = cur
            hop[dep] = hop[cur] + 1
            q.append(dep)
    for node, h in hop.items():
        if node == seed:
            continue
        path, p = [], node
        while p is not None:
            path.append(p.key())
            p = parent[p]
        res.dependents.append({"package": node.key(), "hop": h, "path": list(reversed(path))})
    res.dependents.sort(key=lambda d: (d["hop"], d["package"]))
    res.max_hop = max((d["hop"] for d in res.dependents), default=0)
    return res


# ---------------------------------------------------------------- per-scan

def _adj(edges):
    fwd: dict[str, list[str]] = {}
    rev: dict[str, list[str]] = {}
    for s, d in edges:
        fwd.setdefault(s, []).append(d)
        rev.setdefault(d, []).append(s)
    for v in fwd.values():
        v.sort()
    for v in rev.values():
        v.sort()
    return fwd, rev


def paths_to(root: str, targets: set[str], edges, *, max_paths: int = 3) -> dict[str, list[list[str]]]:
    """Up to `max_paths` shortest root->target paths per target, deterministic order.
    Targets unreachable from root get an empty list."""
    fwd, _ = _adj(edges)
    dist, preds = {root: 0}, {root: []}
    q = deque([root])
    while q:
        n = q.popleft()
        for m in fwd.get(n, []):
            if m not in dist:
                dist[m], preds[m] = dist[n] + 1, [n]
                q.append(m)
            elif dist[m] == dist[n] + 1:
                preds[m].append(n)
    out: dict[str, list[list[str]]] = {}
    for t in targets:
        found: list[list[str]] = []
        stack = [(t, [t])] if t in dist else []
        while stack and len(found) < max_paths:
            node, acc = stack.pop()
            if node == root:
                found.append(list(reversed(acc)))
                continue
            for p in sorted(preds[node], reverse=True):
                stack.append((p, acc + [p]))
        out[t] = found
    return out


def ancestors(seeds: set[str], edges) -> set[str]:
    _, rev = _adj(edges)
    seen = set(seeds)
    q = deque(seeds)
    while q:
        for p in rev.get(q.popleft(), []):
            if p not in seen:
                seen.add(p)
                q.append(p)
    return seen


def project_radius(seed_refs: set[str], components: dict[str, tuple[str, str | None]], edges, root_ref: str,
                   *, complete: bool) -> dict:
    """D05 radius inside one project scan.

    numerator: unique exact name@version on the exposure closure = seeds plus
    every component that depends on a seed (directly or transitively), root excluded;
    denominator: unique exact name@version in the scan.
    Incomplete data or empty denominator -> status UNKNOWN (never "small").
    """
    total = {f"{n}@{v}" for n, v in components.values() if v}
    closure = ancestors(seed_refs, edges) - {root_ref}
    affected = {f"{components[r][0]}@{components[r][1]}" for r in closure if r in components and components[r][1]}
    if not complete or not total:
        return {"status": "UNKNOWN", "affected_versions": len(affected), "total_versions": len(total),
                "ratio": None, "reason": "incomplete scan data" if total else "no versions in scan"}
    return {"status": "KNOWN", "affected_versions": len(affected), "total_versions": len(total),
            "ratio": len(affected) / len(total)}
