"""NT-005: bounded registry possibilities, never an npm installation solver.

All known matching versions are kept, not just the highest version. Client
versions continue to come from lockfiles/SBOMs. Peer and optional declarations
are conditional possibilities, not proof of installation or exploitability.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
import sqlite3

from nodetrust.contracts import PackageId, valid_npm_name
from nodetrust.semver import is_exact, parse_spec, satisfies, sort_versions


def resolve_declaration(name: str, raw: str, versions) -> dict:
    """Resolve against an observed version inventory; never fetch or invent nodes."""
    spec = parse_spec(raw)
    target = spec.target_name or name
    candidates = sorted(set(versions))
    candidates = sort_versions(v for v in candidates if v == v.strip() and satisfies(v, spec))
    reason = None
    if not valid_npm_name(target):
        candidates, reason = [], "invalid_target"
        target = name  # preserve a valid declared identity for an invalid alias
    elif not spec.resolvable:
        candidates, reason = [], "dist_tag" if spec.kind == "tag" else "unsupported_spec"
    elif not candidates:
        reason = "no_matching_version"
    return {
        "target": target,
        "spec_type": "exact" if is_exact(raw) else spec.kind,
        "candidate_versions": candidates,
        "resolution": "registry_possible" if candidates else "unresolved",
        "reason": reason,
    }


@dataclass
class ResolutionGraph:
    root: str
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    unresolved: list[dict] = field(default_factory=list)
    truncated: bool = False
    truncation_reasons: list[str] = field(default_factory=list)
    semantics: str = "registry possibilities; not client installation or exploitability"

    def to_dict(self) -> dict:
        return asdict(self)


def resolve_registry(con: sqlite3.Connection, root: PackageId, *, max_nodes: int = 1000,
                     max_edges: int = 10000, max_depth: int = 25) -> ResolutionGraph:
    """Cycle-safe breadth-first closure of all locally known matching versions.

    Unresolved declarations live separately with a null target version. max_edges
    bounds resolved edges plus unresolved records. Limits explicitly mark a
    partial result. No missing package/version node is created.
    Run inside one read transaction when concurrent ingestion is possible.
    """
    from nodetrust.graph.store import version_row, versions_of

    if max_nodes < 1 or max_edges < 0 or max_depth < 0:
        raise ValueError("invalid traversal limits")
    if (root.ecosystem != "npm" or not valid_npm_name(root.name) or root.name != root.name.lower()
            or root.version != root.version.strip() or not is_exact(root.version)):
        raise ValueError("root must be a canonical exact npm identity")
    if version_row(con, root) is None:
        raise ValueError("root version is absent from the registry snapshot")
    result = ResolutionGraph(root.key())
    seen = {root}
    queue = deque([(root, 0)])
    inventories: dict[str, list[str]] = {}

    def limited(reason):
        result.truncated = True
        if reason not in result.truncation_reasons:
            result.truncation_reasons.append(reason)

    while queue:
        current, depth = queue.popleft()
        declarations = con.execute(
            "SELECT dst_name, spec, kind FROM dep_edge WHERE ecosystem=? AND name=? AND version=? "
            "ORDER BY dst_name, kind, spec", (current.ecosystem, current.name, current.version)).fetchall()
        for declaration in declarations:
            if len(result.edges) + len(result.unresolved) >= max_edges:
                limited("max_edges")
                queue.clear()
                break
            name, raw, kind = declaration["dst_name"], declaration["spec"], declaration["kind"]
            target = parse_spec(raw).target_name or name
            if target not in inventories:
                inventories[target] = versions_of(con, target)
            resolved = resolve_declaration(name, raw, inventories[target])
            base = {"from": asdict(current), "relation": "DEPENDS_ON", "declared_spec": raw, "kind": kind}
            if not resolved["candidate_versions"]:
                result.unresolved.append({**base, "to": {"ecosystem": "npm", "name": resolved["target"], "version": None},
                                          "resolution": "unresolved", "reason": resolved["reason"]})
            for version in resolved["candidate_versions"]:
                candidate = PackageId("npm", target, version)
                if depth >= max_depth:
                    limited("max_depth")
                    continue
                if len(result.edges) + len(result.unresolved) >= max_edges:
                    limited("max_edges")
                    continue
                if candidate not in seen:
                    if len(seen) >= max_nodes:
                        limited("max_nodes")
                        continue
                    seen.add(candidate)
                    queue.append((candidate, depth + 1))
                result.edges.append({**base, "to": asdict(candidate), "resolution": "registry_possible"})
    result.nodes = [asdict(pid) for pid in sorted(seen)]
    return result
