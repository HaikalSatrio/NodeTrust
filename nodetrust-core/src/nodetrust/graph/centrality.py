"""Centrality: stand-in for NT-013 (owner: Haikal).

Registry graph: in-degree and betweenness on a version-level DiGraph, where each
declared dependency points at the highest known version that satisfies it (the
registry-possible resolution). Results are cached with the graph snapshot id and
time they were computed from. Betweenness uses networkx; for graphs above
`exact_limit` nodes it switches to k-sampling and says so.

Client scans: `choke_points` uses dominators from the project root: a
component that dominates many others is the only way those packages enter the
project, i.e. a choke point.
"""

from __future__ import annotations

import sqlite3

import networkx as nx

from nodetrust.contracts import ECOSYSTEM_NPM
from nodetrust.graph.store import snapshot_id
from nodetrust.semver import max_satisfying, parse_spec, sort_versions
from nodetrust.storage import utcnow


def registry_digraph(con: sqlite3.Connection) -> nx.DiGraph:
    g = nx.DiGraph()
    versions: dict[str, list[str]] = {}
    for r in con.execute("SELECT name, version FROM pkg_version WHERE ecosystem=?", (ECOSYSTEM_NPM,)):
        versions.setdefault(r["name"], []).append(r["version"])
        g.add_node(f"{r['name']}@{r['version']}")
    for k in versions:
        versions[k] = sort_versions(versions[k])
    for e in con.execute("SELECT name, version, dst_name, spec FROM dep_edge WHERE ecosystem=?", (ECOSYSTEM_NPM,)):
        sp = parse_spec(e["spec"])
        target = sp.target_name or e["dst_name"]
        if not sp.resolvable or target not in versions:
            continue
        v = max_satisfying(versions[target], sp)
        if v:
            g.add_edge(f"{e['name']}@{e['version']}", f"{target}@{v}")
    return g


def compute_and_cache(con: sqlite3.Connection, *, exact_limit: int = 2000, sample_k: int = 500, seed: int = 7) -> dict:
    g = registry_digraph(con)
    snap = snapshot_id(con)
    n = g.number_of_nodes()
    if n == 0:
        return {"snapshot_id": snap, "nodes": 0, "method": "none"}
    if n <= exact_limit:
        bc, method = nx.betweenness_centrality(g, normalized=True), "exact"
    else:
        bc, method = nx.betweenness_centrality(g, k=min(sample_k, n), normalized=True, seed=seed), f"sampled(k={sample_k})"
    now = utcnow()
    con.execute("DELETE FROM centrality WHERE snapshot_id=?", (snap,))
    for node in g.nodes:
        name, _, version = node.rpartition("@")
        con.execute("INSERT INTO centrality(ecosystem, name, version, in_degree, betweenness, snapshot_id, computed_at) "
                    "VALUES (?,?,?,?,?,?,?)", (ECOSYSTEM_NPM, name, version, g.in_degree(node), bc[node], snap, now))
    return {"snapshot_id": snap, "nodes": n, "edges": g.number_of_edges(), "method": method, "computed_at": now}


def centrality_of(con: sqlite3.Connection, name: str, version: str) -> dict | None:
    r = con.execute("SELECT in_degree, betweenness, snapshot_id, computed_at FROM centrality "
                    "WHERE ecosystem=? AND name=? AND version=? ORDER BY computed_at DESC LIMIT 1",
                    (ECOSYSTEM_NPM, name, version)).fetchone()
    return dict(r) if r else None


def choke_points(root: str, edges, labels: dict[str, str], top: int = 10) -> list[dict]:
    g = nx.DiGraph()
    g.add_node(root)
    g.add_edges_from(edges)
    if root not in g or g.number_of_edges() == 0:
        return []
    idom = nx.immediate_dominators(g, root)
    children: dict[str, list[str]] = {}
    for node, dom in idom.items():
        if node != dom:
            children.setdefault(dom, []).append(node)

    size: dict[str, int] = {}

    def subtree(n: str) -> int:  # iterative post-order to avoid recursion limits
        stack, order = [n], []
        while stack:
            x = stack.pop()
            order.append(x)
            stack.extend(children.get(x, []))
        for x in reversed(order):
            size[x] = 1 + sum(size[c] for c in children.get(x, []))
        return size[n]

    subtree(root)
    out = [{"ref": n, "package": labels.get(n, n), "dominates": size[n] - 1, "dependents_in_project": g.in_degree(n)}
           for n in size if n != root and size[n] > 1]
    out.sort(key=lambda d: (-d["dominates"], d["package"]))
    return out[:top]
