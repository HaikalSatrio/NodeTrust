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


def test_exposed_project_is_held_for_approval(server, tmp_path):
    url, seeded, _ = server
    p = seeded["projects"]["demo-exposed"]
    out_file = tmp_path / "verdict.json"
    code, out = run_ci(url, p["id"], p["ci_key"], mode="enforce", extra=("--out", str(out_file)))
    assert code == 1, out
    assert "decision=pending_approval" in out
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
