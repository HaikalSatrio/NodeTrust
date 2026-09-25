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
from nodetrust.semver import parse_version, sort_versions


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
    cur = _row(con, name, version)
    if cur is None:
        raise KeyError(f"{name}@{version} not in graph")
    base = previous_version(con, name, version)
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
            earlier = {r["publisher"] for r in con.execute(
                "SELECT publisher, version FROM pkg_version WHERE ecosystem=? AND name=? AND publisher IS NOT NULL",
                (ECOSYSTEM_NPM, name)) if parse_version(r["version"]) < parse_version(version)}
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
