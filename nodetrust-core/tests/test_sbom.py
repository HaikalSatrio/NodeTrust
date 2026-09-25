"""NT-018: CycloneDX validation and normalisation."""

import json

import pytest

from nodetrust.contracts import DataQuality, parse_purl
from nodetrust.sbom.cyclonedx import SbomError, parse_cyclonedx
from sbomkit import make_sbom


def test_valid_sbom_normalises_exact_versions_and_relations():
    sb = parse_cyclonedx(make_sbom({"root": ["a@1.0.0", "@s/b@2.0.0"], "a@1.0.0": ["c@1.0.0"]}))
    assert {c.name for c in sb.npm()} == {"a", "@s/b", "c"}
    assert all(c.status == "exact" for c in sb.npm())
    assert sb.direct_refs() == {"a@1.0.0", "@s/b@2.0.0"}
    assert sb.quality() is DataQuality.COMPLETE
    assert sb.coverage()["exact"] == 3


def test_purl_scope_is_decoded():
    assert parse_purl("pkg:npm/%40scope/pkg@1.2.3?foo=bar#x") == ("npm", "@scope/pkg", "1.2.3")
    with pytest.raises(ValueError):
        parse_purl("pkg:npm/a/b/c@1")


@pytest.mark.parametrize("doc,needle", [
    ("{not json", "not valid JSON"),
    (json.dumps([1, 2]), "must be a JSON object"),
    (json.dumps({"bomFormat": "SPDX", "specVersion": "1.5"}), "bomFormat"),
    (json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.2"}), "specVersion"),
    (json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"purl": "pkg:npm/a@1"}]}), "name"),
    (json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "a", "purl": "nope"}]}),
     "purl invalid"),
    (json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "dependencies": {"x": 1}}), "dependencies"),
])
def test_malformed_payloads_are_rejected_clearly(doc, needle):
    with pytest.raises(SbomError) as e:
        parse_cyclonedx(doc)
    assert any(needle in p for p in e.value.problems)


def test_missing_relations_mark_incomplete_not_safe():
    sb = parse_cyclonedx(make_sbom({"root": ["a@1.0.0"]}, with_dependencies=False))
    assert not sb.has_dependency_graph and sb.quality() is DataQuality.INCOMPLETE
    assert any("no dependency relations" in w for w in sb.warnings)


def test_ranges_and_other_ecosystems():
    doc = make_sbom({"root": ["a@1.0.0"]}, extra_components=[
        {"type": "library", "bom-ref": "r", "name": "x", "version": "^1.0.0", "purl": "pkg:npm/x"},
        {"type": "library", "bom-ref": "gh", "name": "actions/checkout", "purl": "pkg:github/actions/checkout@v4"},
    ])
    doc["dependencies"][0]["dependsOn"] += ["r", "gh"]
    sb = parse_cyclonedx(doc)
    cov = sb.coverage()
    assert (cov["unresolved"], cov["out_of_scope"]) == (1, 1)
    assert sb.quality() is DataQuality.INCOMPLETE  # an npm version could not be assessed


def test_duplicate_purls_are_merged_and_unknown_refs_ignored():
    doc = make_sbom({"root": ["a@1.0.0"]})
    doc["components"].append({"type": "library", "bom-ref": "dup", "name": "a", "version": "1.0.0",
                              "purl": "pkg:npm/a@1.0.0"})
    doc["dependencies"].append({"ref": "dup", "dependsOn": ["ghost"]})
    sb = parse_cyclonedx(doc)
    assert len(sb.components) == 1 and any("ghost" in w for w in sb.warnings)


def test_component_limit():
    doc = make_sbom({"root": [f"p{i}@1.0.0" for i in range(20)]})
    with pytest.raises(SbomError):
        parse_cyclonedx(doc, max_components=10)


def test_only_minimal_fields_are_kept():
    doc = make_sbom({"root": ["a@1.0.0"]})
    doc["components"][0].update({"hashes": [{"alg": "SHA-512", "content": "abc"}], "licenses": [], "author": "x",
                                 "properties": [{"name": "syft:location:0:path", "value": "/src/secret/path"}]})
    sb = parse_cyclonedx(doc)
    kept = vars(next(iter(sb.components.values())))
    assert set(kept) == {"ref", "name", "version", "purl", "ecosystem", "status", "scope"}
