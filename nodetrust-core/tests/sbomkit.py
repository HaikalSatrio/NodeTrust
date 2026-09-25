"""Build small CycloneDX 1.5 documents for tests.

make_sbom({"root": ["a@1.0.0", "b@2.0.0"], "a@1.0.0": ["c@1.0.0"]}): keys are
parents ("root" = the project), values are children, all as name@version."""

from nodetrust.contracts import npm_purl


def _split(key):
    name, _, ver = key.rpartition("@")
    return name, ver


def make_sbom(tree: dict, *, with_dependencies: bool = True, extra_components=()):
    comps, deps = {}, []
    for parent, children in tree.items():
        for k in [parent, *children]:
            if k == "root" or k in comps:
                continue
            n, v = _split(k)
            comps[k] = {"type": "library", "bom-ref": k, "name": n, "version": v, "purl": npm_purl(n, v)}
        deps.append({"ref": "root-ref" if parent == "root" else parent, "dependsOn": list(children)})
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"component": {"type": "application", "name": "demo-app", "bom-ref": "root-ref"}},
           "components": list(comps.values()) + list(extra_components)}
    if with_dependencies:
        doc["dependencies"] = deps
    return doc
