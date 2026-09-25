"""Data contract: DRAFT stand-in for NT-003 (owner: Haikal).

Brian's tasks need a shared vocabulary to integrate, so this module fixes one.
It follows the NT-001 draft (D01–D07) but is NOT an agreed contract: Haikal owns
NT-003 and any change here must go through review by both people.

Key rules encoded here:
- Package identity is (ecosystem, name, version); version is always exact.
- DEPENDS_ON edges point from dependent -> dependency.
- Risk tier, evidence status, exposure, data quality and verdict are separate
  fields and never substitute for each other (NT-001 "Dampak ke task").
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import quote, unquote

from nodetrust import SCHEMA_VERSION

__all__ = [
    "SCHEMA_VERSION",
    "PackageId",
    "RiskTier",
    "EvidenceStatus",
    "ExposureStatus",
    "DataQuality",
    "Decision",
    "Mode",
    "tier_for_score",
    "parse_purl",
    "npm_purl",
    "valid_npm_name",
]

ECOSYSTEM_NPM = "npm"

_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9._~-][a-z0-9._~-]*$")


def valid_npm_name(name: str) -> bool:
    # npm allows legacy uppercase names in old packages; we normalise to lowercase
    # for identity but keep the check permissive on length only.
    return 0 < len(name) <= 214 and bool(_NPM_NAME.match(name.lower()))


@dataclass(frozen=True, order=True)
class PackageId:
    ecosystem: str
    name: str
    version: str

    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    @classmethod
    def from_key(cls, key: str) -> "PackageId":
        eco, _, rest = key.partition(":")
        name, sep, version = rest.rpartition("@")
        if not eco or not sep or not name or not version:
            raise ValueError(f"invalid package key: {key!r}")
        return cls(eco, name, version)

    def purl(self) -> str:
        if self.ecosystem != ECOSYSTEM_NPM:
            raise ValueError("only npm purls are supported in the MVP")
        return npm_purl(self.name, self.version)


class RiskTier(str, Enum):
    NORMAL = "NORMAL"
    WATCH = "WATCH"
    INVESTIGATE = "INVESTIGATE"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _TIER_RANK[self]


_TIER_RANK = {RiskTier.NORMAL: 0, RiskTier.WATCH: 1, RiskTier.INVESTIGATE: 2, RiskTier.CRITICAL: 3}


def tier_for_score(score: int) -> RiskTier:
    """Tier boundaries from NT-010 / D04: NORMAL 0–40, WATCH 41–70,
    INVESTIGATE 71–85, CRITICAL >=86. Scores are integers clamped to 0..100
    (rounding happens in scoring, never here)."""
    if not isinstance(score, int) or isinstance(score, bool):
        raise TypeError("score must be an int; round/clamp in the scoring engine")
    if score < 0 or score > 100:
        raise ValueError("score out of range 0..100")
    if score <= 40:
        return RiskTier.NORMAL
    if score <= 70:
        return RiskTier.WATCH
    if score <= 85:
        return RiskTier.INVESTIGATE
    return RiskTier.CRITICAL


class EvidenceStatus(str, Enum):
    """Status of the evidence behind an incident. Only a human sets VERIFIED."""

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    REJECTED = "rejected"


class ExposureStatus(str, Enum):
    EXPOSED = "exposed"  # exact version present in the scan with a path from root
    NOT_EXPOSED = "not_exposed"
    UNKNOWN = "unknown"  # coverage too incomplete to say


class DataQuality(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"  # missing relations / unsupported components
    STALE = "stale"  # required sync older than freshness budget


class Decision(str, Enum):
    PASS = "pass"
    WARN = "warn"
    GATE = "gate"
    PENDING_APPROVAL = "pending_approval"  # build held until a human decides
    UNAVAILABLE = "unavailable"  # assessment could not be made (enforce fails)


class Mode(str, Enum):
    MONITOR = "monitor"
    ENFORCE = "enforce"


def npm_purl(name: str, version: str) -> str:
    # purl spec: namespace '@scope' is percent-encoded as %40scope.
    if name.startswith("@"):
        scope, _, pkg = name.partition("/")
        return f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}@{quote(version, safe='')}"
    return f"pkg:npm/{quote(name, safe='')}@{quote(version, safe='')}"


def parse_purl(purl: str) -> tuple[str, str, str | None]:
    """Return (type, name, version) from a purl. Qualifiers/subpath are dropped.
    For npm the scope is folded into the name ("@scope/pkg")."""
    if not purl.startswith("pkg:"):
        raise ValueError("not a purl")
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    ptype, _, rest = body.partition("/")
    if not ptype or not rest:
        raise ValueError("purl missing type or name")
    version: str | None = None
    if "@" in rest.rsplit("/", 1)[-1]:
        rest, _, v = rest.rpartition("@")
        version = unquote(v)
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        raise ValueError("purl missing name")
    ptype = ptype.lower()
    if ptype == "npm":
        name = "/".join(parts).lower()
        if len(parts) > 2 or (len(parts) == 2 and not parts[0].startswith("@")):
            raise ValueError("invalid npm purl namespace")
    else:
        name = "/".join(parts)
    return ptype, name, version
