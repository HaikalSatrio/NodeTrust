"""Generate the offline demo dataset in fixtures/demo/ (deterministic).

Everything here is SYNTHETIC: package names start with `ntdemo`, advisory ids
start with NTDEMO / MAL-NTDEMO, people are `*-demo`. Nothing describes a real
package, person or incident. Re-run after changing this file; commit the output.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "demo"


def pv(name, ver, time, deps=None, publisher="alice-demo", maintainers=("alice-demo",), scripts=None):
    d = {"name": name, "version": ver, "dependencies": deps or {},
         "maintainers": [{"name": m} for m in maintainers], "_npmUser": {"name": publisher},
         "dist": {"integrity": f"sha512-DEMO-{name}-{ver}".replace("@", "").replace("/", "-")},
         "repository": {"type": "git", "url": f"git+https://example.invalid/{name}.git"}}
    if scripts:
        d["scripts"] = scripts
    return ver, d, time


def packument(name, *versions):
    doc = {"_id": name, "name": name, "dist-tags": {}, "maintainers": [{"name": "alice-demo"}],
           "time": {"modified": max(t for _, _, t in versions)}, "versions": {},
           "description": "SYNTHETIC demo package - not a real npm package"}
    for ver, d, t in versions:
        doc["versions"][ver] = d
        doc["time"][ver] = t
        doc["dist-tags"]["latest"] = ver
    return doc


BASE = [
    packument("ntdemo-helper-x", pv("ntdemo-helper-x", "0.0.1", "2026-08-28T10:00:00.000Z", publisher="mallory-demo",
                                    maintainers=("mallory-demo",))),
    packument("ntdemo-utils",
              pv("ntdemo-utils", "2.0.0", "2025-11-01T10:00:00.000Z"),
              pv("ntdemo-utils", "2.1.0", "2026-03-01T10:00:00.000Z")),
    packument("@ntdemo/logger",
              pv("@ntdemo/logger", "3.0.0", "2026-01-10T10:00:00.000Z", {"ntdemo-utils": "~2.1.0"}),
              pv("@ntdemo/logger", "3.0.1", "2026-04-10T10:00:00.000Z", {"ntdemo-utils": "~2.1.0"})),
    packument("ntdemo-core",
              pv("ntdemo-core", "1.0.0", "2025-12-01T10:00:00.000Z", {"ntdemo-utils": "^2.0.0"}),
              pv("ntdemo-core", "1.1.0", "2026-05-01T10:00:00.000Z",
                 {"ntdemo-utils": "^2.1.0", "@ntdemo/logger": "^3.0.0"})),
    packument("ntdemo-web", pv("ntdemo-web", "5.0.0", "2026-06-01T10:00:00.000Z",
                               {"ntdemo-core": "^1.1.0", "@ntdemo/logger": "^3.0.0"})),
    packument("ntdemo-date", pv("ntdemo-date", "1.0.0", "2026-02-01T10:00:00.000Z"),
              pv("ntdemo-date", "1.0.1", "2026-07-01T10:00:00.000Z")),
    packument("ntdemo-cli", pv("ntdemo-cli", "0.3.0", "2026-06-15T10:00:00.000Z", {"ntdemo-date": "^1.0.0"})),
]

# The "update" the crawler sees later: a new utils release with suspicious metadata changes.
UPDATE = packument("ntdemo-utils",
                   pv("ntdemo-utils", "2.0.0", "2025-11-01T10:00:00.000Z"),
                   pv("ntdemo-utils", "2.1.0", "2026-03-01T10:00:00.000Z"),
                   pv("ntdemo-utils", "2.1.1", "2026-09-01T10:00:00.000Z",
                      {"ntdemo-helper-x": "^0.0.1"}, publisher="mallory-demo",
                      maintainers=("alice-demo", "mallory-demo"), scripts={"postinstall": "node setup.js"}))

OSV = [
    {"id": "NTDEMO-VULN-0001", "modified": "2026-08-01T00:00:00Z", "published": "2026-07-20T00:00:00Z",
     "aliases": ["NTDEMO-CVE-0001"], "summary": "SYNTHETIC demo vulnerability in ntdemo-date (not real)",
     "affected": [{"package": {"ecosystem": "npm", "name": "ntdemo-date"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}]},
]


def cdx(root_name, tree):
    comps, deps = {}, []
    for parent, children in tree.items():
        for k in [parent, *children]:
            if k == "root" or k in comps:
                continue
            n, _, v = k.rpartition("@")
            enc = n.replace("@", "%40")
            comps[k] = {"type": "library", "bom-ref": k, "name": n, "version": v, "purl": f"pkg:npm/{enc}@{v}"}
        deps.append({"ref": "root" if parent == "root" else parent, "dependsOn": children})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": root_name, "bom-ref": "root"}},
            "components": list(comps.values()), "dependencies": deps}


EXPOSED_OLD = {
    "root": ["ntdemo-web@5.0.0", "ntdemo-date@1.0.1"],
    "ntdemo-web@5.0.0": ["ntdemo-core@1.1.0", "@ntdemo/logger@3.0.1"],
    "ntdemo-core@1.1.0": ["ntdemo-utils@2.1.0", "@ntdemo/logger@3.0.1"],
    "@ntdemo/logger@3.0.1": ["ntdemo-utils@2.1.0"],
}
EXPOSED_NEW = {
    "root": ["ntdemo-web@5.0.0", "ntdemo-date@1.0.1"],
    "ntdemo-web@5.0.0": ["ntdemo-core@1.1.0", "@ntdemo/logger@3.0.1"],
    "ntdemo-core@1.1.0": ["ntdemo-utils@2.1.1", "@ntdemo/logger@3.0.1"],
    "@ntdemo/logger@3.0.1": ["ntdemo-utils@2.1.1"],
    "ntdemo-utils@2.1.1": ["ntdemo-helper-x@0.0.1"],
}
CLEAN = {"root": ["ntdemo-cli@0.3.0"], "ntdemo-cli@0.3.0": ["ntdemo-date@1.0.0"]}


def main() -> None:
    for sub in ("packuments", "update", "osv", "sbom"):
        (ROOT / sub).mkdir(parents=True, exist_ok=True)
    for doc in BASE:
        (ROOT / "packuments" / f"{doc['name'].replace('/', '__')}.json").write_text(json.dumps(doc, indent=1) + "\n")
    (ROOT / "update" / "ntdemo-utils.json").write_text(json.dumps(UPDATE, indent=1) + "\n")
    for r in OSV:
        (ROOT / "osv" / f"{r['id']}.json").write_text(json.dumps(r, indent=1) + "\n")
    for name, tree in (("exposed-old", EXPOSED_OLD), ("exposed-new", EXPOSED_NEW), ("clean", CLEAN)):
        (ROOT / "sbom" / f"{name}.cdx.json").write_text(json.dumps(cdx(f"demo-{name}", tree), indent=1) + "\n")
    (ROOT / "README.md").write_text(
        "# Demo fixtures (synthetic)\n\nGenerated by `scripts/make_demo_fixtures.py`. All packages, people and "
        "advisories are fictional (`ntdemo*`, `*-demo`, `NTDEMO-*`). Used by `nodetrust demo` and tests.\n")
    print(f"wrote demo fixtures to {ROOT}")


if __name__ == "__main__":
    main()
