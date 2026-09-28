"""Load the manual fixture into real local Neo4j and verify dependent hop counts."""

import argparse
import json
import os
from pathlib import Path
import tempfile

from check_neo4j import _password_from_dotenv
from nodetrust.contracts import PackageId
from nodetrust.graph.neo4j_spike import Neo4jSpike, Neo4jSpikeError
from nodetrust.graph.store import upsert_packument
from nodetrust.registry.normalize import normalize_packument
from nodetrust.resolver import resolve_registry
from nodetrust.storage import Database

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:7474")
    args = parser.parse_args()
    fixture = json.loads((ROOT / "fixtures/nt004/graph.json").read_text(encoding="utf-8"))
    password = os.environ.get("NEO4J_PASSWORD") or _password_from_dotenv(ROOT / ".env")
    if not password:
        parser.error("set NEO4J_PASSWORD in the environment or .env")
    with tempfile.TemporaryDirectory(prefix="nt004-") as directory:
        db = Database(Path(directory) / "registry.db")
        with db.transaction() as con:
            for doc in fixture["packuments"]:
                record = normalize_packument(doc)
                if record.errors:
                    raise ValueError(record.errors)
                upsert_packument(con, record, source="synthetic-nt004")
            graph = resolve_registry(con, PackageId.from_key(fixture["root"]))
        client = Neo4jSpike(args.url, password)
        try:
            client.load(graph)
            client.load(graph)  # replay must be idempotent
            counts = client.counts()
            actual = client.reverse(fixture["seed"])
            if counts != {"nodes": fixture["expected_nodes"], "edges": fixture["expected_edges"]}:
                raise Neo4jSpikeError("loaded counts differ from the manual fixture")
            if actual != fixture["expected_dependents"]:
                raise Neo4jSpikeError("Neo4j reverse traversal differs from the manual fixture")
            report = {"status": "PASS", "backend": "real Neo4j", **counts,
                      "dependents": actual, "unresolved": len(graph.unresolved),
                      "semantics": graph.semantics}
        finally:
            client.cleanup()
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Neo4jSpikeError, ValueError) as exc:
        print(f"FAIL: {exc}")
        raise SystemExit(1)
