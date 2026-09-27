"""package-lock.json (lockfileVersion 2/3) -> CycloneDX 1.5 with dependency relations.

npm resolution is reproduced from the lockfile's `packages` map: a dependency N
of the package at path P resolves to the nearest `<ancestor>/node_modules/N`,
walking up from P to the root. Workspace links (`"link": true`) are followed.

One component per unique name@version (bom-ref = purl). If the same version is
installed at several paths, their edges are merged; paths stay exact-version.
Dev-only packages are kept (their install scripts run in CI too) and marked
scope "excluded" (not shipped at runtime).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote


class LockfileError(ValueError):
    pass


def npm_purl(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, _, pkg = name.partition("/")
        return f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}@{quote(version, safe='')}"
    return f"pkg:npm/{quote(name, safe='')}@{quote(version, safe='')}"


def _name_from_path(path: str) -> str:
    tail = path.rsplit("node_modules/", 1)[-1]
    return tail


def _parent_dir(path: str) -> str | None:
    """'node_modules/a/node_modules/b' -> 'node_modules/a'; 'node_modules/a' -> '' (root)."""
    if "node_modules/" not in path:
        return "" if path else None
    idx = path.rfind("node_modules/")
    parent = path[:idx].rstrip("/")
    return parent


@dataclass
class Graph:
    root_name: str
    root_version: str | None
    components: dict[str, dict] = field(default_factory=dict)  # purl -> component
    edges: set[tuple[str, str]] = field(default_factory=set)   # (purl|"root", purl)
    warnings: list[str] = field(default_factory=list)


def parse_lockfile(doc: dict, *, include_dev: bool = True) -> Graph:
    if not isinstance(doc, dict):
        raise LockfileError("package-lock.json must be a JSON object")
    ver = doc.get("lockfileVersion")
    if ver not in (2, 3):
        raise LockfileError(f"lockfileVersion {ver!r} is not supported (need 2 or 3, i.e. npm >= 7)")
    packages = doc.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        raise LockfileError("lockfile has no 'packages' map with a root entry")
    root = packages[""]
    g = Graph(root_name=root.get("name") or doc.get("name") or "project", root_version=root.get("version"))

    def resolve_link(path: str) -> str:
        seen = set()
        while path in packages and packages[path].get("link") and path not in seen:
            seen.add(path)
            target = packages[path].get("resolved")
            if not isinstance(target, str):
                break
            path = target
        return path

    def ident(path: str) -> tuple[str, str] | None:
        entry = packages.get(path)
        if not isinstance(entry, dict):
            return None
        name = entry.get("name") or _name_from_path(path)
        version = entry.get("version")
        if not name or not isinstance(version, str):
            return None
        return name.lower(), version

    def node_id(path: str) -> str | None:
        if path == "":
            return "root"
        real = resolve_link(path)  # workspace links point at the workspace package entry
        entry = packages.get(real, {})
        if not include_dev and entry.get("dev"):
            return None
        idt = ident(real)
        if idt is None:
            return None
        purl = npm_purl(*idt)
        if purl not in g.components:
            scope = "excluded" if entry.get("dev") else ("optional" if entry.get("optional") else "required")
            g.components[purl] = {"type": "library", "bom-ref": purl, "name": idt[0], "version": idt[1],
                                  "purl": purl, "scope": scope}
        return purl

    def find(from_path: str, dep: str) -> str | None:
        base = from_path
        while base is not None:
            cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if cand in packages:
                return cand
            base = _parent_dir(base) if base else None
        return None

    for path, entry in packages.items():
        if not isinstance(entry, dict) or entry.get("link"):
            continue
        src = node_id(path)
        if src is None:
            continue
        declared: dict[str, str] = {}
        fields = ["dependencies", "optionalDependencies", "peerDependencies"]
        if path == "" or "node_modules/" not in path:  # root and workspace packages
            if include_dev:
                fields.append("devDependencies")
        for f in fields:
            d = entry.get(f)
            if isinstance(d, dict):
                declared.update({k: v for k, v in d.items() if isinstance(k, str)})
        for dep in sorted(declared):
            target = find(path, dep)
            if target is None:
                optional = dep in (entry.get("optionalDependencies") or {}) or \
                    (entry.get("peerDependenciesMeta") or {}).get(dep, {}).get("optional")
                if not optional:
                    g.warnings.append(f"{path or '(root)'}: dependency {dep} not found in lockfile")
                continue
            dst = node_id(target)
            if dst is not None and dst != src:
                g.edges.add((src, dst))
    return g


def to_cyclonedx(g: Graph) -> dict:
    deps: dict[str, list[str]] = {}
    for s, d in sorted(g.edges):
        deps.setdefault(s, []).append(d)
    root_comp = {"type": "application", "name": g.root_name, "bom-ref": "root"}
    if g.root_version:
        root_comp["version"] = g.root_version
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": root_comp, "tools": {"components": [{"type": "application", "name": "nodetrust-ci"}]}},
        "components": [g.components[k] for k in sorted(g.components)],
        "dependencies": [{"ref": ref, "dependsOn": sorted(set(v))} for ref, v in sorted(deps.items())],
    }


def sbom_from_lockfile(path: Path, *, include_dev: bool = True) -> tuple[dict, list[str]]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise LockfileError(f"{path} not found (commit package-lock.json; other lockfiles are not supported yet)") from e
    except ValueError as e:
        raise LockfileError(f"{path} is not valid JSON: {e}") from e
    g = parse_lockfile(doc, include_dev=include_dev)
    return to_cyclonedx(g), g.warnings
