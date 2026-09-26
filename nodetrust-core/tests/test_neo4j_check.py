"""NT-002: scripts/check_neo4j.py against a stand-in HTTP server on 127.0.0.1 (no real Neo4j)."""

import base64
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "check_neo4j", Path(__file__).resolve().parents[1] / "scripts" / "check_neo4j.py")
check_neo4j = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_neo4j)

PASSWORD = "test-password-123"


class FakeNeo4j(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._json(200, {"neo4j_version": "5.26.0", "neo4j_edition": "community"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        expected = "Basic " + base64.b64encode(f"neo4j:{PASSWORD}".encode()).decode()
        if self.path != "/db/neo4j/tx/commit" or self.headers.get("Authorization") != expected:
            return self._json(401, {"errors": [{"message": "unauthorized"}]})
        assert body["statements"][0]["statement"] == "RETURN 1 AS ok"
        self._json(200, {"results": [{"columns": ["ok"], "data": [{"row": [1]}]}], "errors": []})


@pytest.fixture
def neo4j_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeNeo4j)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_answers_return_1(neo4j_url):
    ok, msg = check_neo4j.check(neo4j_url, PASSWORD)
    assert ok and "5.26.0" in msg and "community" in msg


def test_wrong_password_is_reported_without_echoing_it(neo4j_url):
    ok, msg = check_neo4j.check(neo4j_url, "wrong-password")
    assert not ok and "HTTP 401" in msg and "wrong-password" not in msg


def test_refuses_non_loopback_before_connecting():
    ok, msg = check_neo4j.check("http://neo4j.example.com:7474", PASSWORD)
    assert not ok and "non-loopback" in msg


def test_nothing_listening():
    ok, msg = check_neo4j.check("http://127.0.0.1:9", PASSWORD, timeout=2)
    assert not ok and "not reachable" in msg


def test_password_comes_from_dotenv(tmp_path):
    env = tmp_path / ".env"
    env.write_text("NODETRUST_LOG_LEVEL=INFO\nNEO4J_PASSWORD='from-dotenv-123'\n", encoding="utf-8")
    assert check_neo4j._password_from_dotenv(env) == "from-dotenv-123"
    assert check_neo4j._password_from_dotenv(tmp_path / "missing") is None
