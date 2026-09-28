"""Transport/failure tests. Real Cypher acceptance is scripts/spike_nt004.py."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nodetrust.graph.neo4j_spike import Neo4jSpike, Neo4jSpikeError


@pytest.mark.parametrize("url", ["http://example.com", "http://secret@localhost:7474", "http://localhost/x",
                                 "https://localhost", "http://localhost?x=1"])
def test_only_loopback_origin(url):
    with pytest.raises(ValueError):
        Neo4jSpike(url, "test-password")


@pytest.mark.parametrize("mode", ["error", "malformed", "redirect", "unauthorized", "ok"])
def test_transport_rejects_errors_and_never_echoes_password(mode):
    captured = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            captured.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            code = 302 if mode == "redirect" else 401 if mode == "unauthorized" else 200
            self.send_response(code)
            self.send_header("Location", "http://example.com/")
            self.end_headers()
            body = {"errors": [{"message": "test-password"}]} if mode == "error" else (
                {} if mode == "malformed" else {"results": [{"data": [{"row": [1]}]}], "errors": []})
            self.wfile.write(json.dumps(body).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = Neo4jSpike(f"http://127.0.0.1:{server.server_port}", "test-password")
        if mode == "ok":
            assert client.query("RETURN 1", value="parameter") == [[1]]
        else:
            with pytest.raises(Neo4jSpikeError) as caught:
                client.query("RETURN 1")
            assert "test-password" not in str(caught.value)
        assert captured[0]["statements"][0]["parameters"]["run"] == client.run_id
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
