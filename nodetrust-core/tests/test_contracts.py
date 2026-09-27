"""NT-003: schema fixtures, graph direction and real core/client compatibility."""

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from nodetrust import SCHEMA_VERSION
from nodetrust.api.app import create_app
from nodetrust.config import Settings
from nodetrust.contracts import Decision, PackageId, contract_schema, parse_purl
from nodetrust.graph.blast import reverse_bfs
from nodetrust.graph.store import dependents_of, dependencies_of, upsert_packument
from nodetrust.policy.engine import exit_code_for
from nodetrust.registry.normalize import normalize_packument
from nodetrust.sbom.cyclonedx import parse_cyclonedx

CORE = Path(__file__).resolve().parents[1]
CI = CORE.parent / "nodetrust-ci"
FIXTURE = json.loads((CORE / "fixtures/contracts/nt003.json").read_text(encoding="utf-8"))


def validate(name, value):
    schema = contract_schema(name)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


@pytest.mark.parametrize("name", list(FIXTURE))
def test_contract_examples(name):
    validate(name, FIXTURE[name])


@pytest.mark.parametrize("version", ["1.2.3", "1.2.3-beta.1+demo", "v1.2.3"])
def test_scoped_identity_round_trip(version):
    pid = PackageId("npm", "@ntdemo/logger", version)
    validate("package_id", {"ecosystem": pid.ecosystem, "name": pid.name, "version": pid.version})
    assert PackageId.from_key(pid.key()) == pid
    assert parse_purl(pid.purl()) == ("npm", "@ntdemo/logger", version)


@pytest.mark.parametrize("version", [None, "", "latest", "^1.2.3", "1.2", "01.2.3", "1.2.3-01", "1.2.3\n"])
def test_package_schema_rejects_unresolved_or_malformed_identity(version):
    with pytest.raises(ValidationError):
        validate("package_id", {"ecosystem": "npm", "name": "ntdemo-web", "version": version})


@pytest.mark.parametrize("mutation", [
    {"first_seen": "yesterday"}, {"maintainers": ["same", "same"]},
    {"last_seen": None}, {"source": ""},
])
def test_metadata_schema_rejects_bad_observations(mutation):
    with pytest.raises(ValidationError):
        validate("package_record", {**FIXTURE["package_record"], **mutation})


def test_unresolved_edge_never_invents_a_version():
    edge = copy.deepcopy(FIXTURE["dependency_edge"])
    edge["resolution"] = "unresolved"
    with pytest.raises(ValidationError):
        validate("dependency_edge", edge)
    edge["to"]["version"] = None
    validate("dependency_edge", edge)
    edge["resolution"] = "registry_possible"
    with pytest.raises(ValidationError):
        validate("dependency_edge", edge)


def test_dependency_direction_survives_registry_storage(db):
    # Synthetic dependent -> dependency. Reverse traversal must invert it.
    dependency = {"name": "ntdemo-leaf", "versions": {"2.0.0": {"name": "ntdemo-leaf"}}}
    dependent = {"name": "ntdemo-app", "versions": {"1.0.0": {
        "name": "ntdemo-app", "dependencies": {"ntdemo-leaf": "^2.0.0"}}}}
    with db.transaction() as con:
        for doc in (dependency, dependent):
            upsert_packument(con, normalize_packument(doc))
        deps = dependencies_of(con, PackageId("npm", "ntdemo-app", "1.0.0"))
        assert [(d["target"], d["possible_version"], d["resolution"]) for d in deps] == [
            ("ntdemo-leaf", "2.0.0", "registry_possible")]
        assert dependencies_of(con, PackageId("npm", "ntdemo-leaf", "2.0.0")) == []
        assert dependents_of(con, "ntdemo-leaf", "2.0.0")[0][0] == PackageId("npm", "ntdemo-app", "1.0.0")
        result = reverse_bfs(con, "ntdemo-leaf", "2.0.0")
        assert result.dependents[0]["package"] == "npm:ntdemo-app@1.0.0"
        assert result.dependents[0]["hop"] == 1


def test_fixture_sbom_keeps_forward_edges_and_exact_identity():
    sb = parse_cyclonedx(FIXTURE["scan_submission"]["sbom"])
    assert sb.edges == {("root", "logger")}
    assert sb.components["logger"].status == "exact"
    assert sb.components["logger"].version == "1.2.3-beta.1+demo"


@pytest.fixture
def client_modules(monkeypatch):
    # Both folders are part of this repository: absence is a failed integration,
    # not a skipped contract check.
    assert (CI / "src/nodetrust_ci/cli.py").is_file()
    monkeypatch.syspath_prepend(str(CI / "src"))
    import nodetrust_ci
    from nodetrust_ci import cli, lockfile, summary
    return nodetrust_ci, cli, lockfile, summary


def test_core_client_version_and_all_exit_codes_match(client_modules):
    client, cli, _, _ = client_modules
    assert SCHEMA_VERSION == client.SCHEMA_VERSION == contract_schema("verdict")["x-contract-version"]
    for decision in Decision:
        assert exit_code_for(decision) == cli.DECISION_EXIT[decision.value]


@pytest.mark.parametrize("mode", ["monitor", "enforce"])
@pytest.mark.parametrize("scenario", ["clean", "incomplete", "incident"])
def test_client_sbom_real_api_verdict_and_client_summary(tmp_path, client_modules, mode, scenario):
    _, cli, lockfile, summary = client_modules
    sbom, _ = lockfile.sbom_from_lockfile(CI / "examples/fixture-repo/package-lock.json")
    if scenario == "incomplete":
        sbom.pop("dependencies")
    payload = {"commit": "b" * 40, "branch": "nt003-demo", "run_id": "ntdemo-run.1", "sbom": sbom}
    validate("scan_submission", payload)
    token = "nt003-synthetic-operator-token-0123456789"
    app = create_app(Settings(db_path=tmp_path / "api.db", admin_token=token,
                              snapshot_mode=True, alert_outbox_dir=tmp_path / "out"))
    with TestClient(app) as client:
        operator = {"Authorization": f"Bearer {token}"}
        created = client.post("/v1/projects", json={"name": "ntdemo-contract"}, headers=operator)
        assert created.status_code == 201, created.text
        project = created.json()
        pid = project["project"]["id"]
        admin = {"Authorization": f"Bearer {project['admin_key']}"}
        policy = client.put(f"/v1/projects/{pid}/policy", json={"mode": mode}, headers=admin)
        assert policy.status_code == 200, policy.text
        if scenario == "incident":
            inc = client.post("/v1/incidents", headers=operator, json={
                "title": "NTDEMO synthetic contract incident", "package": "ntdemo-date",
                "affected": {"versions": ["1.0.1"]}, "risk_score": 80})
            assert inc.status_code == 201, inc.text
        key = client.post(f"/v1/projects/{pid}/keys", headers=admin,
                          json={"role": "ci", "label": "ntdemo-contract"}).json()["key"]
        response = client.post(f"/v1/projects/{pid}/scans", json=payload,
                               headers={"Authorization": f"Bearer {key}"})
        assert response.status_code == 200, response.text
        verdict = response.json()
        validate("verdict", verdict)
        assert verdict["exit_code"] == cli.DECISION_EXIT[verdict["decision"]]
        assert verdict["decision"] in summary.render_summary(verdict)
        if scenario == "incident":
            assert verdict["findings"], "contract check must cover a non-empty finding"
        if scenario == "incomplete":
            assert verdict["assessment"] == "unknown"
            assert verdict["decision"] == ("unavailable" if mode == "enforce" else "warn")
        # Responses are extensible; required client fields cannot disappear.
        validate("verdict", {**verdict, "future_optional_field": True})
        bad = {**verdict, "schema_version": "incompatible"}
        with pytest.raises(ValidationError):
            validate("verdict", bad)
        bad = dict(verdict)
        del bad["decision"]
        with pytest.raises(ValidationError):
            validate("verdict", bad)
        error = client.post(f"/v1/projects/{pid}/scans", json={}).json()
        validate("error", error)
