"""Package-version graph on SQLite.

Stand-in for NT-004/NT-008 (owner: Haikal), who will decide on Neo4j. The
interface is kept small so a Neo4j implementation can replace it:
upsert_packument / versions_of / version_row / dependencies_of / dependents_of /
snapshot_id.

Guarantees the crawler relies on (NT-008 acceptance):
- idempotent: replaying the same packument changes nothing but last_seen;
- history: old versions stay queryable (nothing is deleted on unpublish);
- every integrity value seen for a version is kept, so a same-version change is
  visible to the diff engine (NT-009).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field

from nodetrust.contracts import ECOSYSTEM_NPM, PackageId
from nodetrust.registry.normalize import PackumentRecord
from nodetrust.semver import max_satisfying, parse_spec, satisfies, sort_versions
from nodetrust.storage import dumps, utcnow


@dataclass
class UpsertResult:
    name: str
    new_versions: list[str] = field(default_factory=list)
    seen_versions: list[str] = field(default_factory=list)
    integrity_changes: list[tuple[str, str, str]] = field(default_factory=list)  # (version, old, new)
    maintainers_before: list[str] | None = None
    maintainers_after: list[str] = field(default_factory=list)


def upsert_packument(con: sqlite3.Connection, rec: PackumentRecord, *, source: str = "registry",
                     now: str | None = None) -> UpsertResult:
    now = now or utcnow()
    eco = ECOSYSTEM_NPM
    res = UpsertResult(rec.name, maintainers_after=rec.maintainers)
    prev = con.execute("SELECT maintainers_json FROM pkg WHERE ecosystem=? AND name=?", (eco, rec.name)).fetchone()
    if prev:
        res.maintainers_before = json.loads(prev["maintainers_json"])
    con.execute(
        "INSERT INTO pkg(ecosystem, name, maintainers_json, dist_tags_json, registry_modified, fetched_at, source) "
        "VALUES (?,?,?,?,?,?,?) ON CONFLICT(ecosystem, name) DO UPDATE SET "
        "maintainers_json=excluded.maintainers_json, dist_tags_json=excluded.dist_tags_json, "
        "registry_modified=excluded.registry_modified, fetched_at=excluded.fetched_at",
        (eco, rec.name, dumps(rec.maintainers), dumps(rec.dist_tags), rec.modified, now, source))

    for v in rec.versions:
        row = con.execute("SELECT integrity FROM pkg_version WHERE ecosystem=? AND name=? AND version=?",
                          (eco, v.name, v.version)).fetchone()
        if row is None:
            con.execute(
                "INSERT INTO pkg_version(ecosystem, name, version, integrity, published_at, publisher, "
                "maintainers_json, install_scripts_json, repository, deprecated, first_seen, last_seen, source) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (eco, v.name, v.version, v.integrity, v.published_at, v.publisher, dumps(v.maintainers),
                 dumps(v.install_scripts), v.repository, int(v.deprecated), now, now, source))
            for d in v.deps:
                con.execute(
                    "INSERT OR IGNORE INTO dep_edge(ecosystem, name, version, dst_name, spec, kind, spec_kind) "
                    "VALUES (?,?,?,?,?,?,?)", (eco, v.name, v.version, d.name, d.spec, d.kind, d.spec_kind))
            res.new_versions.append(v.version)
        else:
            # Published versions are immutable on npm; we only refresh volatile fields.
            con.execute("UPDATE pkg_version SET last_seen=?, deprecated=? WHERE ecosystem=? AND name=? AND version=?",
                        (now, int(v.deprecated), eco, v.name, v.version))
            res.seen_versions.append(v.version)
            if v.integrity and row["integrity"] and v.integrity != row["integrity"]:
                res.integrity_changes.append((v.version, row["integrity"], v.integrity))
                con.execute("UPDATE pkg_version SET integrity=? WHERE ecosystem=? AND name=? AND version=?",
                            (v.integrity, eco, v.name, v.version))
        if v.integrity:
            con.execute("INSERT OR IGNORE INTO integrity_obs(ecosystem, name, version, integrity, observed_at) "
                        "VALUES (?,?,?,?,?)", (eco, v.name, v.version, v.integrity, now))
    return res


def versions_of(con: sqlite3.Connection, name: str, ecosystem: str = ECOSYSTEM_NPM) -> list[str]:
    rows = con.execute("SELECT version FROM pkg_version WHERE ecosystem=? AND name=?", (ecosystem, name)).fetchall()
    return sort_versions([r["version"] for r in rows])


def version_row(con: sqlite3.Connection, pid: PackageId) -> sqlite3.Row | None:
    return con.execute("SELECT * FROM pkg_version WHERE ecosystem=? AND name=? AND version=?",
                       (pid.ecosystem, pid.name, pid.version)).fetchone()


def known_package(con: sqlite3.Connection, name: str, ecosystem: str = ECOSYSTEM_NPM) -> bool:
    return con.execute("SELECT 1 FROM pkg WHERE ecosystem=? AND name=?", (ecosystem, name)).fetchone() is not None


def dependencies_of(con: sqlite3.Connection, pid: PackageId) -> list[dict]:
    """Declared dependencies with the *registry-possible* resolution: the highest
    known version satisfying the spec. This is not the client's resolved version
    (only a lockfile/SBOM gives that), so callers must not present it as such."""
    out = []
    for e in con.execute("SELECT dst_name, spec, kind, spec_kind FROM dep_edge "
                         "WHERE ecosystem=? AND name=? AND version=? ORDER BY dst_name",
                         (pid.ecosystem, pid.name, pid.version)):
        sp = parse_spec(e["spec"])
        target = sp.target_name or e["dst_name"]
        possible = max_satisfying(versions_of(con, target, pid.ecosystem), sp) if sp.resolvable else None
        out.append({"name": e["dst_name"], "spec": e["spec"], "kind": e["kind"], "target": target,
                    "possible_version": possible,
                    "resolution": "registry_possible" if possible else "unresolved"})
    return out


def dependents_of(con: sqlite3.Connection, name: str, version: str, ecosystem: str = ECOSYSTEM_NPM,
                  kinds: tuple[str, ...] = ("prod", "optional", "peer")) -> list[tuple[PackageId, str, str]]:
    """Package versions whose declared spec for `name` admits `version`.
    Aliases (npm:<name>@range) are matched on their target name."""
    rows = con.execute(
        "SELECT name, version, dst_name, spec, kind FROM dep_edge WHERE ecosystem=? AND "
        "(dst_name=? OR spec LIKE ?)", (ecosystem, name, f"npm:{name}@%")).fetchall()
    out = []
    for r in rows:
        if r["kind"] not in kinds:
            continue
        sp = parse_spec(r["spec"])
        target = sp.target_name or r["dst_name"]
        if target != name or not sp.resolvable:
            continue
        if satisfies(version, sp):
            out.append((PackageId(ecosystem, r["name"], r["version"]), r["spec"], r["kind"]))
    return sorted(out)


def snapshot_id(con: sqlite3.Connection) -> str:
    row = con.execute("SELECT COUNT(*) AS n, COALESCE(MAX(last_seen), '') AS ts FROM pkg_version").fetchone()
    edges = con.execute("SELECT COUNT(*) AS n FROM dep_edge").fetchone()["n"]
    digest = hashlib.sha256(f"{row['n']}|{edges}|{row['ts']}".encode()).hexdigest()[:12]
    return f"graph-{digest}"


def graph_stats(con: sqlite3.Connection) -> dict:
    return {
        "packages": con.execute("SELECT COUNT(*) FROM pkg").fetchone()[0],
        "versions": con.execute("SELECT COUNT(*) FROM pkg_version").fetchone()[0],
        "edges": con.execute("SELECT COUNT(*) FROM dep_edge").fetchone()[0],
        "snapshot_id": snapshot_id(con),
    }
