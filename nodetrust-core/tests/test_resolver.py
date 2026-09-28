"""NT-005: registry possibilities and exact client evidence stay distinct."""

from dataclasses import asdict
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from conftest import packument
from nodetrust.contracts import PackageId, contract_schema
from nodetrust.graph.store import dependencies_of, upsert_packument
from nodetrust.registry.normalize import normalize_packument
from nodetrust.resolver import resolve_declaration, resolve_registry
from nodetrust.semver import parse_spec, satisfies
from nodetrust.sbom.cyclonedx import parse_cyclonedx
from sbomkit import make_sbom

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/nt004/graph.json"


@pytest.fixture
def snapshot(db):
    fixture = json.loads(FIXTURE.read_text())
    with db.transaction() as con:
        for document in fixture["packuments"]:
            upsert_packument(con, normalize_packument(document), source="synthetic-test")
    return db, fixture


def test_transitive_diamond_alias_cycle_and_missing_dependency(snapshot):
    db, fixture = snapshot
    with db.read() as con:
        graph = resolve_registry(con, PackageId.from_key(fixture["root"]))
    assert len(graph.nodes) == fixture["expected_nodes"]
    assert len(graph.edges) == fixture["expected_edges"]
    assert not graph.truncated
    assert len(graph.unresolved) == 1
    assert graph.unresolved[0]["to"]["version"] is None
    assert graph.unresolved[0]["reason"] == "no_matching_version"
    assert all(edge["resolution"] == "registry_possible" for edge in graph.edges)
    assert {edge["kind"] for edge in graph.edges} == {"prod", "peer"}
    assert all(node["name"] != "leaf-alias" for node in graph.nodes)
    validator = Draft202012Validator(contract_schema("dependency_edge"))
    for edge in graph.edges + graph.unresolved:
        validator.validate({key: value for key, value in edge.items() if key != "reason"})


@pytest.mark.parametrize("limits,reason", [
    ({"max_nodes": 2}, "max_nodes"), ({"max_edges": 1}, "max_edges"), ({"max_depth": 1}, "max_depth")])
def test_limits_report_partial_graph_without_dangling_edges(snapshot, limits, reason):
    db, fixture = snapshot
    with db.read() as con:
        result = resolve_registry(con, PackageId.from_key(fixture["root"]), **limits)
    assert result.truncated and reason in result.truncation_reasons
    assert all(edge["from"] in result.nodes and edge["to"] in result.nodes for edge in result.edges)


def test_no_fabricated_root_or_invalid_limits(snapshot):
    db, fixture = snapshot
    with db.read() as con:
        for root in [PackageId("npm", "missing", "1.0.0"), PackageId("npm", "ntdemo-app", "^1")]:
            with pytest.raises(ValueError):
                resolve_registry(con, root)
        with pytest.raises(ValueError):
            resolve_registry(con, PackageId.from_key(fixture["root"]), max_nodes=0)


@pytest.mark.parametrize("raw,reason", [
    ("latest", "dist_tag"), ("next", "dist_tag"), ("workspace:*", "unsupported_spec"),
    ("file:../foo", "unsupported_spec"), ("git+https://example.test/a", "unsupported_spec"),
    ("npm:foo", "unsupported_spec"), ("npm:@scope/foo", "unsupported_spec"),
    ("npm:foo@latest", "unsupported_spec"), ("npm:foo@", "unsupported_spec"),
    ("^3", "no_matching_version"), ("^1.2.3-01", "unsupported_spec")])
def test_unresolved_is_explicit(raw, reason):
    result = resolve_declaration("foo", raw, ["1.2.3", "2.0.0"])
    assert result["resolution"] == "unresolved"
    assert result["candidate_versions"] == []
    assert result["reason"] == reason


def test_exact_range_prerelease_and_equal_precedence_are_deterministic():
    versions = ["1.2.3+z", "1.2.3+a", "1.2.4", "1.3.0-beta", "bad"]
    exact = resolve_declaration("foo", "1.2.3", versions)
    assert exact["spec_type"] == "exact"
    assert exact["candidate_versions"] == ["1.2.3+a", "1.2.3+z"]
    ranged = resolve_declaration("foo", "^1.2.3", reversed(versions))
    assert ranged["candidate_versions"] == ["1.2.3+a", "1.2.3+z", "1.2.4"]
    assert ranged["spec_type"] == "range"
    assert not satisfies("1.2.3", "^1.2.3-01")
    assert not parse_spec("npm:bad/name@^1").resolvable


def test_optional_override_peer_and_original_store_compatibility(db):
    docs = [packument("app", {"1.0.0": {"deps": {"dep": "^1"}, "optional": {"dep": "^2"},
                                         "peer": {"dep": "^1"}}}),
            packument("dep", {"1.0.0": {}, "1.1.0": {}, "2.0.0": {}})]
    with db.transaction() as con:
        for doc in docs:
            upsert_packument(con, normalize_packument(doc))
        graph = resolve_registry(con, PackageId("npm", "app", "1.0.0"))
        existing = dependencies_of(con, PackageId("npm", "app", "1.0.0"))
    assert {(edge["kind"], edge["to"]["version"]) for edge in graph.edges} == {
        ("optional", "2.0.0"), ("peer", "1.0.0"), ("peer", "1.1.0")}
    assert next(row for row in existing if row["kind"] == "peer")["candidate_versions"] == ["1.0.0", "1.1.0"]
    assert next(row for row in existing if row["kind"] == "peer")["possible_version"] == "1.1.0"
    assert asdict(PackageId("npm", "dep", "2.0.0")) in graph.nodes


def test_registry_candidates_do_not_rewrite_exact_client_evidence():
    resolved = resolve_declaration("dep", "^1", ["1.0.0", "1.9.0"])
    client = parse_cyclonedx(make_sbom({"root": ["dep@1.0.0"]}))
    assert resolved["candidate_versions"] == ["1.0.0", "1.9.0"]
    assert [(component.name, component.version) for component in client.npm()] == [("dep", "1.0.0")]


def test_invalid_union_and_wildcards_cannot_fabricate_matches():
    for raw in ("latest || 1.2.3", "1.x.3", "*.2", "x.1.x"):
        assert not parse_spec(raw).resolvable
        assert not satisfies("1.2.3", raw)


def test_long_spec_is_preserved_instead_of_truncated_into_different_range(db):
    raw = ">=1 " * 60 + "<2"
    document = packument("app", {"1.0.0": {"deps": {"dep": raw}}})
    with db.transaction() as con:
        upsert_packument(con, normalize_packument(document))
        upsert_packument(con, normalize_packument(packument("dep", {"1.0.0": {}, "2.0.0": {}})))
        resolved = dependencies_of(con, PackageId("npm", "app", "1.0.0"))[0]
    assert resolved["spec"] == raw
    assert resolved["candidate_versions"] == ["1.0.0"]


def test_node_semver_reference_matrix():
    fixture = json.loads((FIXTURE.parent.parent / "nt005/semver-reference.json").read_text())
    for case in fixture["cases"]:
        actual = [version for version in fixture["versions"] if satisfies(version, case["spec"])]
        assert actual == case["matches"], case["spec"]


def test_unresolved_records_are_bounded_too(db):
    with db.transaction() as con:
        upsert_packument(con, normalize_packument(packument("app", {
            "1.0.0": {"deps": {"missing-a": "^1", "missing-b": "^1", "missing-c": "^1"}}})))
        result = resolve_registry(con, PackageId("npm", "app", "1.0.0"), max_edges=2)
    assert result.truncated and result.truncation_reasons == ["max_edges"]
    assert len(result.unresolved) == 2 and result.edges == []


def test_invalid_alias_remains_a_valid_unresolved_declaration(db):
    with db.transaction() as con:
        upsert_packument(con, normalize_packument(packument("app", {
            "1.0.0": {"deps": {"alias": "npm:bad/name@^1"}}})))
        result = resolve_registry(con, PackageId("npm", "app", "1.0.0"))
    assert result.unresolved[0]["reason"] == "invalid_target"
    assert result.unresolved[0]["to"] == {"ecosystem": "npm", "name": "alias", "version": None}
