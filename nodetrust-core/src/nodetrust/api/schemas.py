"""Request bodies for the public API (response shapes are documented in docs/api.md)."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nodetrust.contracts import EvidenceStatus, valid_npm_name

_COMMIT = re.compile(r"^[0-9a-f]{7,64}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _check_email(v: str | None) -> str | None:
    if v is not None and not _EMAIL.match(v):
        raise ValueError("invalid e-mail address")
    return v


class ProjectCreate(_Strict):
    name: str = Field(min_length=1, max_length=200)
    alert_email: str | None = None

    @field_validator("alert_email")
    @classmethod
    def _email(cls, v):
        return _check_email(v)


class ProjectSettings(_Strict):
    alert_email: str | None = None

    @field_validator("alert_email")
    @classmethod
    def _email(cls, v):
        return _check_email(v)


class KeyCreate(_Strict):
    role: str = Field(pattern="^(ci|admin)$")
    label: str = Field(min_length=1, max_length=100)


class ScanSubmit(_Strict):
    commit: str
    branch: str = Field(min_length=1, max_length=255)
    run_id: str | None = Field(default=None, max_length=100)
    sbom: dict

    @field_validator("commit")
    @classmethod
    def _commit(cls, v: str) -> str:
        v = v.strip().lower()
        if not _COMMIT.match(v):
            raise ValueError("commit must be a hex git SHA (7-64 chars)")
        return v

    @field_validator("branch", "run_id")
    @classmethod
    def _no_ctrl(cls, v):
        if v is not None and _CTRL.search(v):
            raise ValueError("control characters are not allowed")
        return v


class Affected(_Strict):
    versions: list[str] = Field(default_factory=list, max_length=10_000)
    ranges: list[dict] = Field(default_factory=list, max_length=100)


class IncidentCreate(_Strict):
    title: str = Field(min_length=3, max_length=300)
    package: str
    affected: Affected
    risk_score: int = Field(ge=0, le=100)
    is_simulation: bool = False
    detected_at: str | None = None
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("package")
    @classmethod
    def _pkg(cls, v: str) -> str:
        if not valid_npm_name(v):
            raise ValueError("invalid npm package name")
        return v.lower()


class IncidentUpdate(_Strict):
    evidence_status: EvidenceStatus | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    notes: str | None = Field(default=None, max_length=2000)


class TriageDecision(_Strict):
    decision: str = Field(pattern="^(confirm|reject)$")
    note: str = Field(min_length=5, max_length=1000)


class ApprovalDecision(_Strict):
    decision: str = Field(pattern="^(block|allow)$")
    note: str = Field(min_length=5, max_length=1000)


class OverrideCreate(_Strict):
    scan_id: str
    reason: str = Field(min_length=10, max_length=1000)
    hours: float = Field(gt=0, le=24)
    incident_id: str | None = None


class PinRequest(_Strict):
    name: str
    version: str
    bad_versions: list[str] = Field(default_factory=list, max_length=100)
    package_json: str = Field(max_length=1_000_000)


class Watchlist(_Strict):
    names: list[str] = Field(min_length=1, max_length=10_000)

    @field_validator("names")
    @classmethod
    def _names(cls, v):
        bad = [n for n in v if not valid_npm_name(n)]
        if bad:
            raise ValueError(f"invalid package names: {bad[:5]}")
        return [n.lower() for n in v]
