"""Prepare what is sent to NodeTrust.

`enrich` adds dependency relations from the lockfile when a generator's SBOM
(e.g. Syft) lacks them; `minimize` strips the SBOM to the fields NodeTrust uses.
Nothing else leaves the CI job: no source code, file paths, hashes, licences or
tool properties. The exact list is in README ("What is sent").
"""

from __future__ import annotations

from nodetrust_ci.lockfile import npm_purl

KEEP_COMPONENT = ("type", "bom-ref", "name", "version", "purl", "scope")


def _root_ref(sbom: dict) -> str:
    comp = (sbom.get("metadata") or {}).get("component") or {}
    return comp.get("bom-ref") or comp.get("purl") or "root"


def has_root_relations(sbom: dict) -> bool:
    root = _root_ref(sbom)
    return any(d.get("ref") == root and d.get("dependsOn") for d in sbom.get("dependencies") or [])


def enrich(sbom: dict, lock_sbom: dict) -> tuple[dict, list[str]]:
    """Return a copy of `sbom` whose dependency relations come from the lockfile SBOM,
    matched by purl. Components found only in the lockfile are added."""
    notes: list[str] = []
    out = dict(sbom)
    # Syft lists the project's own package (name@version from package.json) as an ordinary library
    # next to its directory root. It is the root, not a dependency; kept, it would be unreachable
    # from the root and turn the whole scan into "coverage incomplete" (found with Syft 1.52).
    lroot = (lock_sbom.get("metadata") or {}).get("component") or {}
    self_purl = npm_purl(lroot["name"], lroot["version"]) if lroot.get("name") and lroot.get("version") else None
    comps = []
    for c in sbom.get("components") or []:
        if not isinstance(c, dict):
            continue
        if self_purl and c.get("purl") == self_purl:
            notes.append(f"the project itself ({self_purl}) is the SBOM root, not a dependency")
            continue
        comps.append(dict(c))
    by_purl = {c.get("purl"): c for c in comps if c.get("purl")}
    ref_for: dict[str, str] = {}
    for c in lock_sbom["components"]:
        if c["purl"] in by_purl:
            ref_for[c["bom-ref"]] = by_purl[c["purl"]].get("bom-ref") or c["purl"]
            by_purl[c["purl"]].setdefault("bom-ref", ref_for[c["bom-ref"]])
        else:
            comps.append(dict(c))
            ref_for[c["bom-ref"]] = c["bom-ref"]
            notes.append(f"added from lockfile (missing in generator SBOM): {c['purl']}")
    root = _root_ref(sbom)
    ref_for["root"] = root
    meta = dict(out.get("metadata") or {})
    if not meta.get("component"):
        meta["component"] = {"type": "application", "name": "project", "bom-ref": root}
    out["metadata"] = meta
    out["components"] = comps
    out["dependencies"] = [{"ref": ref_for[d["ref"]], "dependsOn": [ref_for[x] for x in d["dependsOn"]]}
                           for d in lock_sbom["dependencies"]]
    return out, notes


def minimize(sbom: dict) -> dict:
    def comp(c: dict) -> dict:
        return {k: c[k] for k in KEEP_COMPONENT if k in c}

    flat: list[dict] = []

    def walk(items):
        for c in items or []:
            if isinstance(c, dict):
                flat.append(comp(c))
                walk(c.get("components"))

    walk(sbom.get("components"))
    root = (sbom.get("metadata") or {}).get("component") or {}
    return {
        "bomFormat": sbom.get("bomFormat"), "specVersion": sbom.get("specVersion"), "version": 1,
        "metadata": {"component": {k: root[k] for k in ("type", "name", "version", "bom-ref") if k in root}},
        "components": flat,
        "dependencies": [{"ref": d.get("ref"), "dependsOn": list(d.get("dependsOn") or [])}
                         for d in sbom.get("dependencies") or [] if isinstance(d, dict)],
    }
