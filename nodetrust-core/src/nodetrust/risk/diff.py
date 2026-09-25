"""Metadata diff between package versions (NT-009).

Compares a version with the previous version (semver precedence) of the same
package and returns evidence deltas: dependencies, maintainers, publisher,
install scripts, repository and integrity.

Integrity is handled in two distinct ways (NT-009 acceptance):
- a different hash on a *different* version is expected and never a signal;
- more than one hash observed for the *same* version is flagged, because npm
  does not allow republishing a version. It points at tampering, a mirror
  problem or a data error, and needs a human to look.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field

from nodetrust.contracts import ECOSYSTEM_NPM
from nodetrust.semver import SemverError, Version, parse_version, sort_versions


@dataclass
class Delta:
    name: str
    version: str
    base_version: str | None
    deps_added: list[dict] = field(default_factory=list)
    deps_removed: list[dict] = field(default_factory=list)
    deps_changed: list[dict] = field(default_factory=list)
    maintainers_added: list[str] = field(default_factory=list)
    maintainers_removed: list[str] = field(default_factory=list)
    maintainers_retained: int | None = None  # None = no base version to compare
    publisher: str | None = None
    base_publisher: str | None = None
    publisher_new_to_package: bool = False
    install_scripts_added: list[str] = field(default_factory=list)
    repository_changed: dict | None = None
    same_version_integrity_values: list[str] = field(default_factory=list)
    new_dependency_targets: list[dict] = field(default_factory=list)  # target first published recently
    unknown_dependency_targets: list[str] = field(default_factory=list)
    published_at: str | None = None

    @property
    def same_version_integrity_changed(self) -> bool:
        return len(self.same_version_integrity_values) > 1

    def to_dict(self) -> dict:
        d = asdict(self)
        d["same_version_integrity_changed"] = self.same_version_integrity_changed
        return d


def _row(con, name, version):
    return con.execute("SELECT * FROM pkg_version WHERE ecosystem=? AND name=? AND version=?",
                       (ECOSYSTEM_NPM, name, version)).fetchone()


def _deps(con, name, version) -> dict[tuple[str, str], str]:
    return {(r["dst_name"], r["kind"]): r["spec"] for r in con.execute(
        "SELECT dst_name, kind, spec FROM dep_edge WHERE ecosystem=? AND name=? AND version=?",
        (ECOSYSTEM_NPM, name, version))}


def previous_version(con: sqlite3.Connection, name: str, version: str) -> str | None:
    target = parse_version(version)
    rows = [r["version"] for r in con.execute("SELECT version FROM pkg_version WHERE ecosystem=? AND name=?",
                                              (ECOSYSTEM_NPM, name))]
    lower = [v for v in sort_versions(rows) if parse_version(v) < target]
    return lower[-1] if lower else None


@dataclass(frozen=True)
class _History:
    base_version: str | None  # highest version with lower precedence
    earlier_publishers: frozenset[str]  # publishers of all versions with lower precedence


def _histories(con: sqlite3.Connection, name: str) -> dict[str, _History]:
    """Base version and earlier publishers for every version of a package, from one sort.

    Diffing each new version on its own re-sorted the whole history every time
    (O(n^2 log n)); a first ingest of react (~2,900 versions) took ~10 minutes inside one
    write transaction, blocking every other writer, including CI scan submissions.
    """
    parsed: list[tuple[Version, str, str | None]] = []
    for r in con.execute("SELECT version, publisher FROM pkg_version WHERE ecosystem=? AND name=?",
                         (ECOSYSTEM_NPM, name)):
        try:
            parsed.append((parse_version(r["version"]), r["version"], r["publisher"]))
        except SemverError:
            continue
    parsed.sort(key=lambda t: t[0])  # stable, like sort_versions
    out: dict[str, _History] = {}
    base, publishers, i = None, set(), 0
    while i < len(parsed):
        j = i
        while j < len(parsed) and parsed[j][0] == parsed[i][0]:  # equal precedence (build metadata only)
            j += 1
        group = parsed[i:j]
        hist = _History(base, frozenset(publishers))
        for _, v, _ in group:
            out[v] = hist
        publishers.update(pub for _, _, pub in group if pub)
        base, i = group[-1][1], j
    return out


def _first_published(con, name) -> str | None:
    row = con.execute("SELECT MIN(published_at) AS t FROM pkg_version WHERE ecosystem=? AND name=? "
                      "AND published_at IS NOT NULL", (ECOSYSTEM_NPM, name)).fetchone()
    return row["t"] if row else None


def _days_between(a: str, b: str) -> float | None:
    from datetime import datetime

    try:
        ta = datetime.fromisoformat(a.replace("Z", "+00:00"))
        tb = datetime.fromisoformat(b.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (tb - ta).total_seconds() / 86400


def diff_version(con: sqlite3.Connection, name: str, version: str, *, new_package_days: float = 30.0) -> Delta:
    return diff_versions(con, name, [version], new_package_days=new_package_days)[0]


def diff_versions(con: sqlite3.Connection, name: str, versions, *, new_package_days: float = 30.0) -> list[Delta]:
    """diff_version for several versions of one package, sorting its history once."""
    histories = _histories(con, name)
    return [_diff(con, name, v, histories, new_package_days) for v in versions]


def _diff(con: sqlite3.Connection, name: str, version: str, histories: dict[str, _History],
          new_package_days: float) -> Delta:
    cur = _row(con, name, version)
    if cur is None:
        raise KeyError(f"{name}@{version} not in graph")
    hist = histories.get(version)
    if hist is None:
        parse_version(version)  # raises SemverError for an invalid version, as before
        hist = _History(None, frozenset())
    base = hist.base_version
    d = Delta(name=name, version=version, base_version=base, publisher=cur["publisher"],
              published_at=cur["published_at"])
    d.same_version_integrity_values = sorted(r["integrity"] for r in con.execute(
        "SELECT integrity FROM integrity_obs WHERE ecosystem=? AND name=? AND version=?",
        (ECOSYSTEM_NPM, name, version)))

    cur_deps = _deps(con, name, version)
    cur_maint = set(json.loads(cur["maintainers_json"]))
    cur_scripts = set(json.loads(cur["install_scripts_json"]))

    if base is not None:
        b = _row(con, name, base)
        base_deps = _deps(con, name, base)
        for key in sorted(set(cur_deps) - set(base_deps)):
            d.deps_added.append({"name": key[0], "kind": key[1], "spec": cur_deps[key]})
        for key in sorted(set(base_deps) - set(cur_deps)):
            d.deps_removed.append({"name": key[0], "kind": key[1], "spec": base_deps[key]})
        for key in sorted(set(cur_deps) & set(base_deps)):
            if cur_deps[key] != base_deps[key]:
                d.deps_changed.append({"name": key[0], "kind": key[1], "from": base_deps[key], "to": cur_deps[key]})
        base_maint = set(json.loads(b["maintainers_json"]))
        d.maintainers_added = sorted(cur_maint - base_maint)
        d.maintainers_removed = sorted(base_maint - cur_maint)
        d.maintainers_retained = len(cur_maint & base_maint)
        d.base_publisher = b["publisher"]
        d.install_scripts_added = sorted(cur_scripts - set(json.loads(b["install_scripts_json"])))
        if (b["repository"] or None) != (cur["repository"] or None) and b["repository"]:
            d.repository_changed = {"from": b["repository"], "to": cur["repository"]}
        if cur["publisher"]:
            earlier = hist.earlier_publishers
            d.publisher_new_to_package = bool(earlier) and cur["publisher"] not in earlier
        # new dependencies whose target package is itself very new
        for dep in d.deps_added:
            first = _first_published(con, dep["name"])
            if first is None:
                d.unknown_dependency_targets.append(dep["name"])
            elif cur["published_at"]:
                age = _days_between(first, cur["published_at"])
                if age is not None and 0 <= age <= new_package_days:
                    d.new_dependency_targets.append({"name": dep["name"], "first_published": first,
                                                     "age_days": round(age, 1)})
    return d
