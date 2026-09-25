"""OSV as the first advisory source (NT-011).

Two ways in:
- offline import of OSV JSON records (a directory, or the per-ecosystem
  `all.zip` export), the default, works without network;
- `OsvClient.query_package`, which calls the OSV API through the gated transport.

Rules:
- records are matched on ecosystem ("npm") + name + affected versions/ranges;
- source and fetch time are stored with each record;
- records sharing an id or alias are grouped (group_id) so one issue reported
  under GHSA-/CVE-/MAL- ids is shown once, listing every id;
- withdrawn records are kept for history but never matched;
- a vulnerability advisory is NOT evidence of malware or compromise. MAL-*
  (OpenSSF malicious-package) reports create an UNVERIFIED incident candidate
  that a human must verify.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from nodetrust.contracts import ECOSYSTEM_NPM
from nodetrust.incidents import affects, create_incident
from nodetrust.obs import get_logger, log
from nodetrust.registry.transport import NetworkDisabled, Transport, TransportError, fetch_with_retry
from nodetrust.storage import Database, dumps, utcnow

_log = get_logger("osv")

MALICIOUS_REPORT_SCORE = 80  # proposal: INVESTIGATE -> e-mail + triage; never auto-verified
_OSV_ECOSYSTEM = "npm"


class InvalidOsvRecord(ValueError):
    pass


@dataclass
class ImportReport:
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped_other_ecosystem: int = 0
    invalid: list[str] = field(default_factory=list)
    incidents_created: int = 0


def _validate(doc) -> dict:
    if not isinstance(doc, dict):
        raise InvalidOsvRecord("record is not an object")
    rid = doc.get("id")
    if not isinstance(rid, str) or not rid:
        raise InvalidOsvRecord("missing id")
    if not isinstance(doc.get("modified"), str):
        raise InvalidOsvRecord(f"{rid}: missing modified")
    aff = doc.get("affected", [])
    if not isinstance(aff, list):
        raise InvalidOsvRecord(f"{rid}: affected is not a list")
    return doc


def _npm_affected(doc: dict) -> list[dict]:
    out = []
    for a in doc.get("affected", []):
        pkg = a.get("package") if isinstance(a, dict) else None
        if not isinstance(pkg, dict) or pkg.get("ecosystem") != _OSV_ECOSYSTEM or not isinstance(pkg.get("name"), str):
            continue
        out.append({"name": pkg["name"].lower(),
                    "versions": [v for v in a.get("versions", []) if isinstance(v, str)],
                    "ranges": [r for r in a.get("ranges", []) if isinstance(r, dict)]})
    return out


def _group_for(con: sqlite3.Connection, ids: set[str]) -> str:
    marks = ",".join("?" * len(ids))
    groups = {r["group_id"] for r in con.execute(
        f"SELECT DISTINCT a.group_id FROM advisory_alias x JOIN advisory a ON a.id = x.advisory_id "
        f"WHERE x.alias IN ({marks})", sorted(ids))}
    candidates = ids | groups
    gid = min(candidates)
    # merge older groups into the canonical one
    for g in groups:
        if g != gid:
            con.execute("UPDATE advisory SET group_id=? WHERE group_id=?", (gid, g))
    return gid


def import_records(db: Database, docs: Iterable, *, source: str, fetched_at: str | None = None) -> ImportReport:
    fetched_at = fetched_at or utcnow()
    rep = ImportReport()
    with db.transaction() as con:
        for raw in docs:
            try:
                doc = _validate(raw)
            except InvalidOsvRecord as e:
                rep.invalid.append(str(e))
                continue
            affected = _npm_affected(doc)
            if not affected:
                rep.skipped_other_ecosystem += 1
                continue
            rid = doc["id"]
            digest = hashlib.sha256(dumps(doc).encode()).hexdigest()
            aliases = sorted({a for a in doc.get("aliases", []) if isinstance(a, str)})
            kind = "malicious_report" if rid.startswith("MAL-") else "vulnerability"
            existing = con.execute("SELECT raw_sha256 FROM advisory WHERE id=?", (rid,)).fetchone()
            if existing and existing["raw_sha256"] == digest:
                rep.unchanged += 1
                continue
            gid = _group_for(con, {rid, *aliases})
            con.execute(
                "INSERT INTO advisory(id, source, aliases_json, summary, kind, modified, withdrawn, fetched_at, "
                "affected_json, raw_sha256, group_id) VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "source=excluded.source, aliases_json=excluded.aliases_json, summary=excluded.summary, "
                "kind=excluded.kind, modified=excluded.modified, withdrawn=excluded.withdrawn, "
                "fetched_at=excluded.fetched_at, affected_json=excluded.affected_json, "
                "raw_sha256=excluded.raw_sha256, group_id=excluded.group_id",
                (rid, source, dumps(aliases), (doc.get("summary") or "")[:500], kind, doc["modified"],
                 doc.get("withdrawn"), fetched_at, dumps(affected), digest, gid))
            con.execute("DELETE FROM advisory_alias WHERE advisory_id=?", (rid,))
            for alias in {rid, *aliases}:
                con.execute("INSERT OR IGNORE INTO advisory_alias(alias, advisory_id) VALUES (?,?)", (alias, rid))
            con.execute("DELETE FROM advisory_pkg WHERE advisory_id=?", (rid,))
            for a in affected:
                con.execute("INSERT OR IGNORE INTO advisory_pkg(advisory_id, ecosystem, name) VALUES (?,?,?)",
                            (rid, ECOSYSTEM_NPM, a["name"]))
            if existing:
                rep.updated += 1
            else:
                rep.inserted += 1
            if kind == "malicious_report" and not doc.get("withdrawn"):
                for a in affected:
                    ref = f"osv:{rid}:{a['name']}"
                    if con.execute("SELECT 1 FROM incident WHERE source='osv' AND source_ref=?", (ref,)).fetchone():
                        continue
                    if not (a["versions"] or a["ranges"]):
                        continue
                    create_incident(
                        con, title=f"{rid}: reported malicious package {a['name']} (unverified)", name=a["name"],
                        affected={"versions": a["versions"], "ranges": a["ranges"]},
                        risk_score=MALICIOUS_REPORT_SCORE, source="osv", source_ref=ref,
                        detected_at=doc.get("published") or doc["modified"],
                        notes="Created from an OSV malicious-package report. Requires human verification of the "
                              "source before it is treated as confirmed compromise.")
                    rep.incidents_created += 1
    db.set_sync("intel:osv", ok=True, detail={"source": source, "inserted": rep.inserted, "updated": rep.updated})
    log(_log, logging.INFO, "osv.import", source=source, inserted=rep.inserted, updated=rep.updated,
        unchanged=rep.unchanged, invalid=len(rep.invalid), incidents=rep.incidents_created)
    return rep


def iter_dir(path: Path) -> Iterable:
    for p in sorted(Path(path).glob("*.json")):
        try:
            yield json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            yield {"_invalid": p.name}


def iter_zip(path: Path, max_member_bytes: int = 5 * 1024 * 1024) -> Iterable:
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json") or info.file_size > max_member_bytes:
                continue
            try:
                yield json.loads(zf.read(info))
            except ValueError:
                yield {"_invalid": info.filename}


def advisories_for(con: sqlite3.Connection, name: str, version: str) -> list[dict]:
    """Non-withdrawn advisories affecting name@version, one entry per alias group."""
    rows = con.execute(
        "SELECT a.* FROM advisory a JOIN advisory_pkg p ON p.advisory_id = a.id "
        "WHERE p.ecosystem=? AND p.name=? AND a.withdrawn IS NULL", (ECOSYSTEM_NPM, name)).fetchall()
    groups: dict[str, dict] = {}
    for r in rows:
        hit = any(a["name"] == name and affects(a, version) for a in json.loads(r["affected_json"]))
        if not hit:
            continue
        g = groups.setdefault(r["group_id"], {"group_id": r["group_id"], "ids": [], "aliases": set(), "kind": r["kind"],
                                              "summary": r["summary"], "sources": set(), "fetched_at": r["fetched_at"],
                                              "modified": r["modified"]})
        g["ids"].append(r["id"])
        g["aliases"].update(json.loads(r["aliases_json"]))
        g["sources"].add(r["source"])
        if r["kind"] == "malicious_report":
            g["kind"] = "malicious_report"
        g["fetched_at"] = max(g["fetched_at"], r["fetched_at"])
    out = []
    for g in groups.values():
        g["ids"].sort()
        g["aliases"] = sorted(g["aliases"] - set(g["ids"]))
        g["sources"] = sorted(g["sources"])
        g["is_evidence_of_compromise"] = False
        out.append(g)
    return sorted(out, key=lambda g: g["group_id"])


class OsvClient:
    def __init__(self, db: Database, transport: Transport, api_url: str, timeout: float = 20.0,
                 sleep=time.sleep):
        self.db, self.transport, self.api_url, self.timeout = db, transport, api_url.rstrip("/"), timeout
        self.sleep = sleep

    def query_package(self, name: str) -> ImportReport:
        body = json.dumps({"package": {"ecosystem": _OSV_ECOSYSTEM, "name": name}}).encode()
        try:
            resp = fetch_with_retry(self.transport, "POST", f"{self.api_url}/query", timeout=self.timeout,
                                    max_bytes=20 * 1024 * 1024, body=body, sleep=self.sleep,
                                    headers={"content-type": "application/json"})
        except (TransportError, NetworkDisabled) as e:
            self.db.set_sync("intel:osv", ok=False, error=str(e))
            raise
        if resp.status != 200:
            self.db.set_sync("intel:osv", ok=False, error=f"HTTP {resp.status}")
            raise TransportError(f"OSV HTTP {resp.status}")
        try:
            vulns = json.loads(resp.body).get("vulns", [])
        except ValueError as e:
            self.db.set_sync("intel:osv", ok=False, error="invalid JSON")
            raise TransportError("OSV returned invalid JSON") from e
        return import_records(self.db, vulns, source="osv-api")
