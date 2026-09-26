"""Local end-to-end: nodetrust-ci (subprocess, real HTTP over 127.0.0.1) against a
running nodetrust-core seeded with the synthetic demo data. No internet.

Needs nodetrust-ci cloned next to nodetrust-core (same parent directory); skipped otherwise.
Run from nodetrust-core:  python -m pytest e2e -q -p no:asyncio
"""

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1]
CI_REPO = CORE.parent / "nodetrust-ci"
if not (CI_REPO / "src" / "nodetrust_ci" / "cli.py").is_file():
    pytest.skip("nodetrust-ci is not cloned next to nodetrust-core", allow_module_level=True)
sys.path.insert(0, str(CORE / "src"))

import uvicorn  # noqa: E402

from nodetrust.api.app import create_app  # noqa: E402
from nodetrust.config import Settings  # noqa: E402
from nodetrust.demo import seed_demo  # noqa: E402
from nodetrust.storage import Database  # noqa: E402

CLI = CI_REPO / "src" / "nodetrust_ci" / "cli.py"
REPO = CI_REPO / "examples" / "fixture-repo"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    s = Settings(db_path=tmp / "e2e.db", snapshot_mode=True, alert_outbox_dir=tmp / "outbox")
    seeded = seed_demo(Database(s.db_path), CORE / "fixtures" / "demo")
    port = free_port()
    srv = uvicorn.Server(uvicorn.Config(create_app(s), host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", seeded, tmp
    srv.should_exit = True
    th.join(timeout=5)


def run_ci(url, project, key, mode="monitor", commit="f" * 40, timeout="10", extra=()):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "NODETRUST_"))}
    env.update({"NODETRUST_API_KEY": key, "PYTHONIOENCODING": "utf-8"})
    p = subprocess.run([sys.executable, str(CLI), "submit", "--api-url", url, "--project", project,
                        "--mode", mode, "--commit", commit, "--branch", "main", "--run-id", "e2e.1",
                        "--timeout", timeout, *extra],
                       cwd=REPO, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
    return p.returncode, p.stdout + p.stderr


def test_exposed_project_is_gated(server, tmp_path):
    url, seeded, _ = server
    p = seeded["projects"]["demo-exposed"]
    out_file = tmp_path / "verdict.json"
    code, out = run_ci(url, p["id"], p["ci_key"], mode="enforce", extra=("--out", str(out_file)))
    assert code == 1, out
    assert "decision=gate" in out  # small project radius under D05 option 1, gate pre-authorised
    assert p["ci_key"] not in out  # key never printed (no GITHUB_ACTIONS -> no mask line either)
    import json
    v = json.loads(out_file.read_text(encoding="utf-8"))
    paths = [" > ".join(pth) for f in v["findings"] for pth in f["paths"]]
    assert any("ntdemo-utils@2.1.1" in x for x in paths)
    assert "simulation" in v["labels"] and "offline_snapshot" in v["labels"]


def test_clean_project_in_monitor_mode_never_blocks(server):
    url, seeded, _ = server
    p = seeded["projects"]["demo-clean"]
    code, out = run_ci(url, p["id"], p["ci_key"], mode="monitor", commit="e" * 40)
    assert code == 0, out
    assert "decision=warn" in out  # the fixture repo contains the simulated incident's version


def test_invalid_key_is_a_config_error(server):
    url, seeded, _ = server
    p = seeded["projects"]["demo-clean"]
    code, out = run_ci(url, p["id"], "ntk_deadbeef_nope", mode="monitor")
    assert code == 2 and "rejected" in out


def test_cross_project_key_is_rejected(server):
    url, seeded, _ = server
    code, out = run_ci(url, seeded["projects"]["demo-exposed"]["id"], seeded["projects"]["demo-clean"]["ci_key"])
    assert code == 2 and "project not found" in out


@pytest.mark.parametrize("mode,code", [("monitor", 0), ("enforce", 3)])
def test_unreachable_server(mode, code):
    port = free_port()  # nothing listens here
    rc, out = run_ci(f"http://127.0.0.1:{port}", "prj_x", "ntk_a_b", mode=mode, timeout="3")
    assert rc == code, out
    assert "UNKNOWN" in out or "unavailable" in out


# ---------------------------------------------------------------- action.yml glue
# Runs the "Submit to NodeTrust" step of action.yml the way a runner does: expressions expanded into
# env, the run: script under bash, outputs read back from $GITHUB_OUTPUT. Only the runner itself is
# missing (network, GitHub-hosted image).

def _bash():
    import shutil

    if os.name == "nt":  # never WSL's System32\bash.exe: it would run inside Linux
        git_bash = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
        return str(git_bash) if git_bash.is_file() else None
    return shutil.which("bash")


def run_action_submit(url, project, key, tmp_path, **inputs):
    import re

    yaml = pytest.importorskip("yaml")
    bash = _bash()
    if not bash:
        pytest.skip("bash not available")
    action = yaml.safe_load((CI_REPO / "action.yml").read_text(encoding="utf-8"))
    values = {k: str(v.get("default", "")) for k, v in action["inputs"].items()}
    values.update({"api-url": url, "project-id": project, "api-key": key, **inputs})
    ctx = {"runner.temp": tmp_path.as_posix(), "github.action_path": CI_REPO.as_posix()}

    def expand(text):
        def one(m):
            expr = m.group(1)
            return values[expr[len("inputs."):]] if expr.startswith("inputs.") else ctx[expr]
        return re.sub(r"\$\{\{\s*([\w.-]+)\s*\}\}", one, str(text))

    step = next(s for s in action["runs"]["steps"] if s.get("id") == "submit")
    assert "${{" not in step["run"]
    shim = tmp_path / "bin"
    shim.mkdir(exist_ok=True)  # the runner image has python3; Windows may only have a Store stub
    (shim / "python3").write_text(f'#!/bin/sh\nexec "{Path(sys.executable).as_posix()}" "$@"\n', newline="\n")
    out, summary = tmp_path / "github_output", tmp_path / "step_summary"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "NODETRUST_"))}
    env.update({k: expand(v) for k, v in step["env"].items()})
    env.update({"GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary), "GITHUB_ACTIONS": "true",
                "GITHUB_SHA": "a" * 40, "GITHUB_REF_NAME": "main", "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1",
                "PYTHONIOENCODING": "utf-8"})
    p = subprocess.run([bash, "-c", f'export PATH="$(cygpath -u "{shim}" 2>/dev/null || echo "{shim}"):$PATH"\n'
                        + step["run"]], cwd=REPO / expand(step["working-directory"]), env=env,
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    outputs = dict(line.split("=", 1) for line in out.read_text(encoding="utf-8").splitlines() if "=" in line)
    return p.returncode, p.stdout + p.stderr, outputs


def test_action_submit_step_writes_outputs_and_exit_code(server, tmp_path):
    url, seeded, _ = server
    p = seeded["projects"]["demo-exposed"]
    code, out, outputs = run_action_submit(url, p["id"], p["ci_key"], tmp_path, mode="enforce")
    assert code == 1, out
    assert outputs["decision"] == "gate" and outputs["exit-code"] == "1"
    assert Path(outputs["verdict-path"]).is_file()
    assert f"::add-mask::{p['ci_key']}" in out  # masked before anything else can print it
    assert p["ci_key"] not in out.replace(f"::add-mask::{p['ci_key']}", "")


def test_action_submit_step_without_dev_packages(server, tmp_path):
    url, seeded, _ = server
    p = seeded["projects"]["demo-clean"]
    code, out, outputs = run_action_submit(url, p["id"], p["ci_key"], tmp_path, **{"include-dev": "false"})
    assert code == 0, out
    assert outputs["exit-code"] == "0" and outputs["decision"] in ("pass", "warn")
