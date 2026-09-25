"""Normalise npm packuments into internal records (NT-007).

Stored per version: name, version, dependencies (prod/optional/peer with their
declared spec), integrity, publisher, maintainers, publish time, install scripts,
repository and deprecation. Maintainer e-mail addresses are dropped on purpose:
usernames are enough to detect maintainer changes and we avoid storing PII.

Invalid pieces are rejected individually and reported; one bad version does not
poison the rest of the packument.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nodetrust.contracts import valid_npm_name
from nodetrust.semver import is_exact, parse_spec

INSTALL_SCRIPT_HOOKS = ("preinstall", "install", "postinstall")
DEP_KINDS = ("prod", "optional", "peer")


@dataclass
class DepRecord:
    name: str
    spec: str
    kind: str  # prod | optional | peer
    spec_kind: str  # range | alias | tag | unsupported


@dataclass
class VersionRecord:
    name: str
    version: str
    integrity: str | None
    published_at: str | None
    publisher: str | None
    maintainers: list[str]
    install_scripts: list[str]
    repository: str | None
    deprecated: bool
    deps: list[DepRecord]


@dataclass
class PackumentRecord:
    name: str
    maintainers: list[str]
    dist_tags: dict[str, str]
    modified: str | None
    unpublished: bool
    versions: list[VersionRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class InvalidPackument(ValueError):
    pass


def _names(people: Any) -> list[str]:
    out: set[str] = set()
    if isinstance(people, list):
        for p in people:
            if isinstance(p, dict) and isinstance(p.get("name"), str):
                out.add(p["name"].strip())
            elif isinstance(p, str):
                # "Name <email> (url)" form: keep only the name part
                out.add(p.split("<", 1)[0].strip())
    return sorted(n for n in out if n)


def _repo(v: Any) -> str | None:
    if isinstance(v, str):
        return v[:500]
    if isinstance(v, dict) and isinstance(v.get("url"), str):
        return v["url"][:500]
    return None


def _integrity(dist: Any) -> str | None:
    if not isinstance(dist, dict):
        return None
    integ = dist.get("integrity")
    if isinstance(integ, str) and integ.strip():
        return integ.strip()
    shasum = dist.get("shasum")
    if isinstance(shasum, str) and len(shasum) == 40:
        return f"sha1hex-{shasum.lower()}"
    return None


def _deps(doc: dict, errors: list[str], where: str) -> list[DepRecord]:
    out: dict[tuple[str, str], DepRecord] = {}
    optional = doc.get("optionalDependencies") or {}
    for field_name, kind in (("dependencies", "prod"), ("optionalDependencies", "optional"),
                             ("peerDependencies", "peer")):
        raw = doc.get(field_name)
        if raw is None:
            continue
        if not isinstance(raw, dict):
            errors.append(f"{where}: {field_name} is not an object")
            continue
        for dname, spec in raw.items():
            if not isinstance(dname, str) or not isinstance(spec, str) or not valid_npm_name(dname):
                errors.append(f"{where}: invalid {field_name} entry {dname!r}")
                continue
            dname_l = dname.lower()
            k = kind
            # npm merges optionalDependencies into dependencies at publish time;
            # record such entries once, as optional.
            if kind == "prod" and isinstance(optional, dict) and dname in optional:
                continue
            out[(dname_l, k)] = DepRecord(dname_l, spec.strip()[:200], k, parse_spec(spec).kind)
    return sorted(out.values(), key=lambda d: (d.kind, d.name))


def normalize_packument(doc: Any, expected_name: str | None = None) -> PackumentRecord:
    if not isinstance(doc, dict):
        raise InvalidPackument("packument is not an object")
    name = doc.get("name") or doc.get("_id")
    if not isinstance(name, str) or not valid_npm_name(name):
        raise InvalidPackument(f"invalid package name: {name!r}")
    name = name.lower()
    if expected_name and name != expected_name.lower():
        raise InvalidPackument(f"packument name {name!r} does not match requested {expected_name!r}")

    times = doc.get("time") if isinstance(doc.get("time"), dict) else {}
    tags = {k: v for k, v in (doc.get("dist-tags") or {}).items() if isinstance(k, str) and isinstance(v, str)} \
        if isinstance(doc.get("dist-tags"), dict) else {}
    rec = PackumentRecord(
        name=name,
        maintainers=_names(doc.get("maintainers")),
        dist_tags=tags,
        modified=times.get("modified") if isinstance(times.get("modified"), str) else None,
        unpublished="unpublished" in times,
    )
    versions = doc.get("versions")
    if versions is None:
        versions = {}
    if not isinstance(versions, dict):
        raise InvalidPackument("versions is not an object")

    for ver, vdoc in versions.items():
        where = f"{name}@{ver}"
        if not isinstance(ver, str) or not is_exact(ver):
            rec.errors.append(f"{where}: version is not exact semver")
            continue
        if not isinstance(vdoc, dict):
            rec.errors.append(f"{where}: version document is not an object")
            continue
        vname = vdoc.get("name")
        if isinstance(vname, str) and vname.lower() != name:
            rec.errors.append(f"{where}: version document names {vname!r}")
            continue
        scripts = vdoc.get("scripts") if isinstance(vdoc.get("scripts"), dict) else {}
        publisher = vdoc.get("_npmUser")
        rec.versions.append(VersionRecord(
            name=name,
            version=ver,
            integrity=_integrity(vdoc.get("dist")),
            published_at=times.get(ver) if isinstance(times.get(ver), str) else None,
            publisher=publisher.get("name") if isinstance(publisher, dict) and isinstance(publisher.get("name"), str)
            else None,
            maintainers=_names(vdoc.get("maintainers")),
            install_scripts=sorted(h for h in INSTALL_SCRIPT_HOOKS if isinstance(scripts.get(h), str)),
            repository=_repo(vdoc.get("repository")),
            deprecated=bool(vdoc.get("deprecated")),
            deps=_deps(vdoc, rec.errors, where),
        ))
    rec.versions.sort(key=lambda v: v.version)
    return rec
