"""CycloneDX JSON intake: validate and normalise (NT-018).

What we keep from an SBOM (and nothing else, see docs/data-sent.md):
component bom-ref, purl, name, version, scope, and the dependency relations.
Hashes, licences, file paths, authors and any other field are dropped.

Normalisation:
- npm components with an exact semver version -> status "exact";
- npm components with a missing/range version -> "unresolved" (never guessed);
- non-npm components -> "out_of_scope" (D01: npm only). They are reported, but
  do not degrade npm data quality;
- duplicate components (same purl, different bom-ref) are merged;
- the dependency graph is required to compute paths and blast radius. When it is
  missing, or npm components are unreachable from the root, the scan quality is
  INCOMPLETE and exposure/radius are reported as UNKNOWN rather than safe.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field

from nodetrust.contracts import DataQuality, parse_purl, valid_npm_name
from nodetrust.semver import is_exact

SUPPORTED_SPEC_VERSIONS = {"1.4", "1.5", "1.6"}
ROOT_REF_FALLBACK = "nodetrust:root"


class SbomError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems[:5]))
        self.problems = problems


@dataclass
class Component:
    ref: str
    name: str
    version: str | None
    purl: str | None
    ecosystem: str | None
    status: str  # exact | unresolved | out_of_scope
    scope: str | None = None


@dataclass
class NormalizedSbom:
    spec_version: str
    sha256: str
    root_ref: str
    root_name: str | None
    components: dict[str, Component] = field(default_factory=dict)
    edges: set[tuple[str, str]] = field(default_factory=set)
    has_dependency_graph: bool = False
    warnings: list[str] = field(default_factory=list)

    def npm(self) -> list[Component]:
        return [c for c in self.components.values() if c.ecosystem == "npm"]

    def direct_refs(self) -> set[str]:
        return {d for s, d in self.edges if s == self.root_ref}

    def reachable_from_root(self) -> set[str]:
        adj: dict[str, list[str]] = {}
        for s, d in self.edges:
            adj.setdefault(s, []).append(d)
        seen, q = {self.root_ref}, deque([self.root_ref])
        while q:
            for n in adj.get(q.popleft(), []):
                if n not in seen:
                    seen.add(n)
                    q.append(n)
        seen.discard(self.root_ref)
        return seen

    def coverage(self) -> dict:
        npm = self.npm()
        reachable = self.reachable_from_root() if self.has_dependency_graph else set()
        orphans = sorted(c.ref for c in npm if c.ref not in reachable) if self.has_dependency_graph else []
        return {
            "components": len(self.components),
            "npm_components": len(npm),
            "exact": sum(c.status == "exact" for c in npm),
            "unresolved": sum(c.status == "unresolved" for c in npm),
            "out_of_scope": sum(c.status == "out_of_scope" for c in self.components.values()),
            "dependency_graph": self.has_dependency_graph,
            "unreachable_from_root": len(orphans),
        }

    def quality(self) -> DataQuality:
        cov = self.coverage()
        if not cov["dependency_graph"] or cov["unresolved"] or cov["unreachable_from_root"]:
            return DataQuality.INCOMPLETE
        return DataQuality.COMPLETE


def _flatten(components, out: list, problems: list[str], path: str, depth: int = 0) -> None:
    if depth > 10:
        problems.append(f"{path}: nesting deeper than 10 levels")
        return
    if not isinstance(components, list):
        problems.append(f"{path} must be a list")
        return
    for i, c in enumerate(components):
        where = f"{path}[{i}]"
        if not isinstance(c, dict):
            problems.append(f"{where} must be an object")
            continue
        out.append((where, c))
        if "components" in c:
            _flatten(c["components"], out, problems, f"{where}.components", depth + 1)


def _component(where: str, c: dict, idx: int, problems: list[str], warnings: list[str]) -> Component | None:
    name = c.get("name")
    if not isinstance(name, str) or not name.strip():
        problems.append(f"{where}.name is required")
        return None
    purl = c.get("purl")
    version = c.get("version") if isinstance(c.get("version"), str) else None
    ref = c.get("bom-ref") if isinstance(c.get("bom-ref"), str) and c.get("bom-ref") else (purl or f"anon:{idx}")
    scope = c.get("scope") if c.get("scope") in ("required", "optional", "excluded") else None
    if purl is not None and not isinstance(purl, str):
        problems.append(f"{where}.purl must be a string")
        return None
    if not purl:
        warnings.append(f"{where} ({name}) has no purl; treated as out of scope")
        return Component(ref, name, version, None, None, "out_of_scope", scope)
    try:
        ptype, pname, pversion = parse_purl(purl)
    except ValueError as e:
        problems.append(f"{where}.purl invalid: {e}")
        return None
    if ptype != "npm":
        return Component(ref, pname, pversion or version, purl, ptype, "out_of_scope", scope)
    if not valid_npm_name(pname):
        # Cannot exist on the npm registry; never queue a fetch for it.
        warnings.append(f"{where}: {pname[:80]!r} is not a valid npm package name; not assessed")
        return Component(ref, pname[:214], pversion or version, purl, None, "out_of_scope", scope)
    v = pversion or version
    status = "exact" if v and is_exact(v) else "unresolved"
    if status == "unresolved":
        warnings.append(f"{where} ({pname}) has no exact version ({v!r}); not assessed")
    return Component(ref, pname, v, purl, "npm", status, scope)


def parse_cyclonedx(raw: bytes | str | dict, *, max_components: int = 50_000) -> NormalizedSbom:
    if isinstance(raw, dict):
        doc = raw
        digest_src = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    else:
        digest_src = raw.encode() if isinstance(raw, str) else raw
        try:
            doc = json.loads(digest_src)
        except (ValueError, UnicodeDecodeError) as e:
            raise SbomError([f"not valid JSON: {e}"]) from e
    problems: list[str] = []
    if not isinstance(doc, dict):
        raise SbomError(["SBOM must be a JSON object"])
    if doc.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat must be 'CycloneDX'")
    spec = doc.get("specVersion")
    if spec not in SUPPORTED_SPEC_VERSIONS:
        problems.append(f"specVersion {spec!r} not supported (expected one of {sorted(SUPPORTED_SPEC_VERSIONS)})")
    if problems:
        raise SbomError(problems)

    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    root = meta.get("component") if isinstance(meta.get("component"), dict) else None
    root_ref = (root or {}).get("bom-ref") or ((root or {}).get("purl")) or ROOT_REF_FALLBACK
    sb = NormalizedSbom(spec_version=spec, sha256=hashlib.sha256(digest_src).hexdigest(), root_ref=str(root_ref),
                        root_name=(root or {}).get("name"))

    flat: list = []
    _flatten(doc.get("components", []), flat, problems, "components")
    if len(flat) > max_components:
        raise SbomError([f"too many components: {len(flat)} > {max_components}"])

    by_purl: dict[str, str] = {}
    alias: dict[str, str] = {}
    for i, (where, c) in enumerate(flat):
        comp = _component(where, c, i, problems, sb.warnings)
        if comp is None:
            continue
        if comp.ref == sb.root_ref:
            continue  # the project itself sometimes appears in components too
        if comp.purl and comp.purl in by_purl:
            alias[comp.ref] = by_purl[comp.purl]
            continue
        if comp.ref in sb.components:
            problems.append(f"{where}: duplicate bom-ref {comp.ref!r} with different purl")
            continue
        sb.components[comp.ref] = comp
        if comp.purl:
            by_purl[comp.purl] = comp.ref
    if problems:
        raise SbomError(problems)

    deps = doc.get("dependencies")
    if deps is not None and not isinstance(deps, list):
        raise SbomError(["dependencies must be a list"])
    known = set(sb.components) | {sb.root_ref}
    for i, d in enumerate(deps or []):
        if not isinstance(d, dict) or not isinstance(d.get("ref"), str):
            raise SbomError([f"dependencies[{i}] must be an object with a string ref"])
        src = alias.get(d["ref"], d["ref"])
        targets = d.get("dependsOn", [])
        if not isinstance(targets, list):
            raise SbomError([f"dependencies[{i}].dependsOn must be a list"])
        if src not in known:
            sb.warnings.append(f"dependencies[{i}] refers to unknown ref {d['ref']!r}; ignored")
            continue
        for t in targets:
            if not isinstance(t, str):
                raise SbomError([f"dependencies[{i}].dependsOn entries must be strings"])
            dst = alias.get(t, t)
            if dst not in known:
                sb.warnings.append(f"dependencies[{i}] -> unknown ref {t!r}; ignored")
                continue
            if dst != src:
                sb.edges.add((src, dst))
    sb.has_dependency_graph = any(s == sb.root_ref for s, _ in sb.edges)
    if not sb.has_dependency_graph:
        sb.warnings.append("SBOM has no dependency relations from the root component: paths and blast radius "
                           "cannot be computed (coverage incomplete)")
    return sb
