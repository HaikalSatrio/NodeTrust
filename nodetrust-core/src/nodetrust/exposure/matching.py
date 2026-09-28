"""Incident -> project exposure matching. Stand-in for NT-021 (owner: Haikal).

Exact versions from the scan are matched against each incident's affected
versions/ranges. A component with the incident's package name but no exact
version gives exposure UNKNOWN (never "not exposed"). Paths are shortest
root -> component paths from the SBOM relations; radius is D05 inside this
project only. Nothing about other projects is read or returned.
"""

from __future__ import annotations

import sqlite3

from nodetrust.contracts import DataQuality, EvidenceStatus, ExposureStatus, tier_for_score
from nodetrust.exposure.scans import ScanView
from nodetrust.graph.blast import paths_to, project_radius
from nodetrust.incidents import affects, list_incidents
from nodetrust.policy.engine import Finding


def match_scan(con: sqlite3.Connection, scan: ScanView, *, max_paths: int = 3) -> list[Finding]:
    by_name: dict[str, list[tuple[str, dict]]] = {}
    for ref, c in scan.components.items():
        if c["ecosystem"] == "npm":
            by_name.setdefault(c["name"], []).append((ref, c))
    findings: list[Finding] = []
    complete = scan.quality is DataQuality.COMPLETE
    npm_versions = scan.npm_versions()
    for inc in list_incidents(con, names=by_name):
        comps = by_name.get(inc["name"])
        if not comps:
            continue
        hit_refs = [r for r, c in comps if c["status"] == "exact" and affects(inc["affected"], c["version"])]
        unknown = [r for r, c in comps if c["status"] != "exact"]
        if hit_refs:
            exposure = ExposureStatus.EXPOSED
        elif unknown:
            exposure = ExposureStatus.UNKNOWN
        else:
            continue  # present, but in unaffected versions only
        refs = hit_refs or unknown
        paths = paths_to(scan.root_ref, set(refs), scan.edges, max_paths=max_paths) if scan.edges else {}
        labelled = [[scan.label(n) for n in p] for r in sorted(refs) for p in paths.get(r, [])]
        radius = project_radius(set(hit_refs), npm_versions, scan.edges, scan.root_ref,
                                complete=complete and bool(hit_refs))
        findings.append(Finding(
            incident_id=inc["id"], title=inc["title"], package=inc["name"],
            tier=tier_for_score(inc["risk_score"]), risk_score=inc["risk_score"],
            evidence_status=EvidenceStatus(inc["evidence_status"]), evidence_version=inc["evidence_version"],
            is_simulation=inc["is_simulation"], source=inc["source"], exposure=exposure,
            versions=sorted({scan.components[r]["version"] or "?" for r in refs}), refs=sorted(refs),
            paths=labelled, radius=radius))
    return findings
