"""nodetrust-ci unit tests (NT-024): lockfile -> SBOM, enrichment, minimisation,
client retry/budget behaviour and exit-code mapping. No network."""

import json
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nodetrust_ci import EXIT_BLOCKED, EXIT_CONFIG, EXIT_OK, EXIT_UNAVAILABLE  # noqa: E402
from nodetrust_ci import cli  # noqa: E402
from nodetrust_ci.client import ApiConfigError, ApiUnavailable, HttpResult, submit  # noqa: E402
from nodetrust_ci.lockfile import LockfileError, parse_lockfile, sbom_from_lockfile  # noqa: E402
from nodetrust_ci.sbom import enrich, has_root_relations, minimize  # noqa: E402
from nodetrust_ci.summary import annotation, render_summary  # noqa: E402

FIX = ROOT / "examples" / "fixture-repo"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    real = socket.socket.connect

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise RuntimeError(f"outbound connection attempted: {address!r}")
        return real(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


def edges(sbom):
    return {(d["ref"], t) for d in sbom["dependencies"] for t in d["dependsOn"]}


P = lambda n, v: f"pkg:npm/{n.replace('@', '%40')}@{v}"  # noqa: E731


def test_lockfile_resolution_matches_npm_layout():
    sbom, warnings = sbom_from_lockfile(FIX / "package-lock.json")
    assert warnings == []
    names = {(c["name"], c["version"]) for c in sbom["components"]}
    assert ("ntdemo-date", "1.0.0") in names and ("ntdemo-date", "1.0.1") in names  # nested copy kept
    e = edges(sbom)
    assert ("root", P("ntdemo-web", "5.0.0")) in e and ("root", P("ntdemo-cli", "0.3.0")) in e
    assert (P("ntdemo-cli", "0.3.0"), P("ntdemo-date", "1.0.0")) in e          # nested wins
    assert (P("ntdemo-cli", "0.3.0"), P("ntdemo-date", "1.0.1")) not in e
    assert (P("@ntdemo/logger", "3.0.1"), P("ntdemo-utils", "2.1.1")) in e       # scoped
    assert (P("ntdemo-utils", "2.1.1"), P("ntdemo-helper-x", "0.0.1")) in e
    scope = {c["name"] + "@" + c["version"]: c["scope"] for c in sbom["components"]}
    assert scope["ntdemo-cli@0.3.0"] == "excluded" and scope["ntdemo-web@5.0.0"] == "required"


def test_no_dev_excludes_dev_packages():
    sbom, _ = sbom_from_lockfile(FIX / "package-lock.json", include_dev=False)
    assert "ntdemo-cli" not in {c["name"] for c in sbom["components"]}


def test_workspace_links_and_missing_deps():
    doc = {"lockfileVersion": 3, "packages": {
        "": {"name": "mono", "dependencies": {"ws-a": "*", "ghost": "^1"}, "optionalDependencies": {"opt": "1"}},
        "node_modules/ws-a": {"resolved": "packages/a", "link": True},
        "packages/a": {"name": "ws-a", "version": "0.1.0", "dependencies": {"left": "^1.0.0"}},
        "node_modules/left": {"version": "1.2.0"}}}
    g = parse_lockfile(doc)
    assert ("root", P("ws-a", "0.1.0")) in g.edges and (P("ws-a", "0.1.0"), P("left", "1.2.0")) in g.edges
    assert any("ghost" in w for w in g.warnings) and not any("opt" in w for w in g.warnings)


def test_unsupported_lockfiles_are_clear_errors(tmp_path):
    with pytest.raises(LockfileError, match="lockfileVersion"):
        parse_lockfile({"lockfileVersion": 1, "dependencies": {}})
    with pytest.raises(LockfileError, match="not found"):
        sbom_from_lockfile(tmp_path / "package-lock.json")


def test_enrich_generator_sbom_without_relations_and_minimize():
    lock, _ = sbom_from_lockfile(FIX / "package-lock.json")
    syft_like = {"bomFormat": "CycloneDX", "specVersion": "1.5",
                 "metadata": {"component": {"type": "file", "name": ".", "bom-ref": "abc-root"}},
                 "components": [{"type": "library", "bom-ref": "syft-1", "name": "ntdemo-web", "version": "5.0.0",
                                 "purl": P("ntdemo-web", "5.0.0"), "licenses": [{"license": {"id": "MIT"}}],
                                 "properties": [{"name": "syft:location:0:path", "value": "/home/runner/work/secret"}],
                                 "hashes": [{"alg": "SHA-512", "content": "x"}]}]}
    assert not has_root_relations(syft_like)
    enriched, notes = enrich(syft_like, lock)
    assert has_root_relations(enriched) and any("added from lockfile" in n for n in notes)
    assert ("abc-root", "syft-1") in edges(enriched)  # mapped onto the generator's own refs
    small = minimize(enriched)
    blob = json.dumps(small)
    assert "/home/runner" not in blob and "licenses" not in blob and "hashes" not in blob
    assert set(small) == {"bomFormat", "specVersion", "version", "metadata", "components", "dependencies"}


def test_enrich_drops_the_project_itself_that_syft_lists_as_a_library():
    # Shape seen with Syft 1.52 (cyclonedx-json@1.6) on examples/fixture-repo: the directory is the
    # metadata root, the project's own package appears as a library, plus a `file` component.
    lock, _ = sbom_from_lockfile(FIX / "package-lock.json")
    root = lock["metadata"]["component"]
    self_purl = P(root["name"], root["version"])
    syft = {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"component": {"type": "file", "name": ".", "bom-ref": "dir-root"}},
            "components": [
                {"type": "library", "bom-ref": "self-id", "name": root["name"], "version": root["version"],
                 "purl": self_purl},
                {"type": "library", "bom-ref": "web-id", "name": "ntdemo-web", "version": "5.0.0",
                 "purl": P("ntdemo-web", "5.0.0")},
                {"type": "file", "bom-ref": "lockfile-id", "name": "/package-lock.json"}]}
    enriched, notes = enrich(syft, lock)
    assert self_purl not in {c.get("purl") for c in enriched["components"]}
    assert any("is the SBOM root" in n for n in notes)
    reachable, todo = set(), ["dir-root"]
    rel = {d["ref"]: d["dependsOn"] for d in enriched["dependencies"]}
    while todo:
        for nxt in rel.get(todo.pop(), []):
            if nxt not in reachable:
                reachable.add(nxt)
                todo.append(nxt)
    npm = {c["bom-ref"] for c in enriched["components"] if (c.get("purl") or "").startswith("pkg:npm/")}
    assert npm <= reachable  # every npm component hangs off the root: coverage is complete


# ---------------------------------------------------------------- client

def fake_clock():
    t = [0.0]
    return t, (lambda: t[0]), (lambda s: t.__setitem__(0, t[0] + s))


def test_client_retries_transient_errors_then_succeeds():
    t, clock, sleep = fake_clock()
    calls = []

    def send(url, data, headers, timeout):
        calls.append(timeout)
        assert headers["Authorization"] == "Bearer k"
        if len(calls) < 3:
            return HttpResult(503, b"")
        return HttpResult(200, b'{"decision":"pass"}')

    assert submit("https://nt.example", "p", "k", {}, send=send, clock=clock, sleep=sleep)["decision"] == "pass"
    assert len(calls) == 3


def test_client_budget_exhaustion_is_unavailable():
    t, clock, sleep = fake_clock()

    def send(url, data, headers, timeout):
        t[0] += timeout  # every call hangs until its timeout
        raise TimeoutError()

    with pytest.raises(ApiUnavailable):
        submit("https://nt.example", "p", "k", {}, budget_s=60, send=send, clock=clock, sleep=sleep)
    assert t[0] <= 61


def test_client_does_not_retry_auth_errors_and_requires_https():
    calls = []

    def send(url, data, headers, timeout):
        calls.append(1)
        return HttpResult(401, b'{"error":{"message":"invalid or revoked credentials"}}')

    with pytest.raises(ApiConfigError, match="revoked"):
        submit("https://nt.example", "p", "k", {}, send=send)
    assert calls == [1]
    with pytest.raises(ApiConfigError, match="https"):
        submit("http://nt.example", "p", "k", {}, send=send)


# ---------------------------------------------------------------- cli / exit codes

def verdict(decision, mode="monitor", **kw):
    return {"schema_version": "2026-09.draft1", "decision": decision, "assessment": "ok", "mode": mode,
            "policy_version": 1, "labels": [], "exit_code": 0,
            "data_quality": {"status": "complete", "graph_snapshot": "graph-x"},
            "scan": {"commit": "a" * 40, "branch": "main", "scan_id": "scan_1", "run_id": "1.1"},
            "findings": [], "reasons": [{"code": "no_exposure", "message": "No known incident..."}], **kw}


@pytest.fixture
def ci_env(monkeypatch, tmp_path):
    monkeypatch.chdir(FIX)
    monkeypatch.setenv("NODETRUST_API_KEY", "ntk_abc_secret")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    out = tmp_path / "gh_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    return ["submit", "--api-url", "https://nt.example", "--project", "prj_1", "--commit", "a" * 40,
            "--branch", "main", "--summary", str(tmp_path / "summary.md")], out, tmp_path


@pytest.mark.parametrize("decision,code", [("pass", EXIT_OK), ("warn", EXIT_OK), ("gate", EXIT_BLOCKED),
                                           ("pending_approval", EXIT_BLOCKED), ("unavailable", EXIT_UNAVAILABLE)])
def test_exit_codes_follow_server_decision(ci_env, monkeypatch, decision, code, capsys):
    argv, out, tmp = ci_env
    seen = {}

    def fake_submit(url, project, key, payload, budget_s):
        seen["payload"] = payload
        return verdict(decision)

    monkeypatch.setattr(cli, "submit", fake_submit)
    assert cli.main(argv) == code
    assert f"decision={decision}" in out.read_text(encoding="utf-8")
    assert "## NodeTrust" in (tmp / "summary.md").read_text(encoding="utf-8")
    printed = capsys.readouterr().out
    assert "::add-mask::ntk_abc_secret" in printed
    assert printed.count("ntk_abc_secret") == 1  # only inside the mask command
    assert seen["payload"]["sbom"]["dependencies"], "relations must be sent"


@pytest.mark.parametrize("mode,code", [("monitor", EXIT_OK), ("enforce", EXIT_UNAVAILABLE)])
def test_api_unreachable_depends_on_mode(ci_env, monkeypatch, mode, code):
    argv, out, tmp = ci_env

    def down(*a, **k):
        raise ApiUnavailable("no assessment within 60s (attempt 3: HTTP 503)")

    monkeypatch.setattr(cli, "submit", down)
    assert cli.main(argv + ["--mode", mode]) == code
    assert "UNKNOWN" in (tmp / "summary.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("mode", ["monitor", "enforce"])
def test_invalid_key_fails_in_both_modes(ci_env, monkeypatch, mode):
    argv, _, _ = ci_env

    def rejected(*a, **k):
        raise ApiConfigError(401, "invalid or revoked credentials")

    monkeypatch.setattr(cli, "submit", rejected)
    assert cli.main(argv + ["--mode", mode]) == EXIT_CONFIG


def test_missing_key_on_fork_pr_is_explained(ci_env, monkeypatch, capsys):
    argv, _, _ = ci_env
    monkeypatch.setenv("NODETRUST_API_KEY", "")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    assert cli.main(argv) == EXIT_CONFIG
    assert "forks" in capsys.readouterr().out


def test_annotation_escaping_and_summary_labels():
    assert annotation("error", "a%b\nc", title="x:y,z") == "::error title=x%3Ay%2Cz::a%25b%0Ac"
    md = render_summary(verdict("warn", labels=["simulation", "offline_snapshot"]))
    assert "SIMULATION" in md and "Offline snapshot" in md and "heuristic" in md
