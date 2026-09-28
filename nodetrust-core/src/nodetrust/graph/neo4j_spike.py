"""Isolated NT-004 experiment against Neo4j 5.26's transactional HTTP API.

This is not a replacement production store. Each run owns a random namespace;
cleanup can only remove that run's synthetic fixture nodes. No APOC/GDS needed.
"""

from __future__ import annotations

import base64
from collections import deque
import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid

from nodetrust.contracts import PackageId
from nodetrust.resolver import ResolutionGraph


class Neo4jSpikeError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Neo4jSpikeError("Neo4j redirect refused")


class Neo4jSpike:
    def __init__(self, url: str, password: str, *, timeout: float = 10):
        parsed = urlsplit(url)
        if (parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"}):
            raise ValueError("spike requires a loopback HTTP origin")
        if not password:
            raise ValueError("Neo4j password is required")
        self.url = url.rstrip("/") + "/db/neo4j/tx/commit"
        self.run_id = str(uuid.uuid4())
        self.timeout = timeout
        self._auth = "Basic " + base64.b64encode(f"neo4j:{password}".encode()).decode()
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def query(self, statement: str, **parameters) -> list[list]:
        parameters["run"] = self.run_id
        request = urllib.request.Request(self.url, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": self._auth},
            data=json.dumps({"statements": [{"statement": statement, "parameters": parameters}]}).encode())
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = json.load(response)
        except urllib.error.HTTPError as exc:
            raise Neo4jSpikeError(f"Neo4j HTTP {exc.code}") from None
        except (OSError, ValueError):
            raise Neo4jSpikeError("Neo4j unavailable or invalid JSON response") from None
        if body.get("errors"):
            raise Neo4jSpikeError("Neo4j rejected the spike query")
        try:
            return [row["row"] for row in body["results"][0]["data"]]
        except (KeyError, IndexError, TypeError):
            raise Neo4jSpikeError("Unexpected Neo4j response") from None

    def load(self, graph: ResolutionGraph) -> None:
        if graph.truncated:
            raise ValueError("cannot prove a spike with a truncated graph")
        nodes = [{**node, "key": PackageId(**node).key()} for node in graph.nodes]
        keys = {node["key"] for node in nodes}
        edges = []
        for edge in graph.edges:
            source, target = PackageId(**edge["from"]).key(), PackageId(**edge["to"]).key()
            if source not in keys or target not in keys or edge["resolution"] != "registry_possible":
                raise ValueError("spike edges must join observed registry nodes")
            edges.append({"source": source, "target": target, "spec": edge["declared_spec"], "kind": edge["kind"]})
        # A single transaction creates the complete fixture or rolls it all back.
        self.query("""
            UNWIND $nodes AS n
            MERGE (p:NT004PackageVersion {run_id: $run, key: n.key})
            SET p.ecosystem = n.ecosystem, p.name = n.name, p.version = n.version,
                p.source = 'synthetic-nt004'
            WITH count(*) AS ignored
            UNWIND $edges AS e
            MATCH (a:NT004PackageVersion {run_id: $run, key: e.source})
            MATCH (b:NT004PackageVersion {run_id: $run, key: e.target})
            MERGE (a)-[r:DEPENDS_ON {declared_spec: e.spec, kind: e.kind}]->(b)
            SET r.resolution = 'registry_possible'
            RETURN count(r)
        """, nodes=nodes, edges=edges)

    def counts(self) -> dict:
        nodes = self.query("MATCH (n:NT004PackageVersion {run_id: $run}) RETURN count(n)")[0][0]
        edges = self.query("MATCH (a:NT004PackageVersion {run_id: $run})-[r:DEPENDS_ON]->"
                           "(b:NT004PackageVersion {run_id: $run}) RETURN count(r)")[0][0]
        return {"nodes": nodes, "edges": edges}

    def reverse(self, seed: str, *, max_nodes: int = 1000) -> list[dict]:
        rows = self.query("MATCH (n:NT004PackageVersion {run_id: $run, key: $seed}) RETURN n.key", seed=seed)
        if not rows:
            raise ValueError("seed is absent from the loaded Neo4j fixture")
        seen, queue, result = {seed}, deque([(seed, 0)]), []
        while queue:
            current, hop = queue.popleft()
            rows = self.query("MATCH (d:NT004PackageVersion {run_id: $run})-[:DEPENDS_ON]->"
                              "(n:NT004PackageVersion {run_id: $run, key: $seed}) "
                              "RETURN DISTINCT d.key ORDER BY d.key", seed=current)
            for (key,) in rows:
                if key in seen:
                    continue
                if len(result) >= max_nodes:
                    raise Neo4jSpikeError("spike traversal exceeded max_nodes")
                seen.add(key)
                queue.append((key, hop + 1))
                result.append({"package": key, "hop": hop + 1})
        return sorted(result, key=lambda row: (row["hop"], row["package"]))

    def cleanup(self) -> None:
        self.query("MATCH (n:NT004PackageVersion {run_id: $run}) DETACH DELETE n")
