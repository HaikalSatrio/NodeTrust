"""Per-project policy, versioned (NT-022).

Defaults follow NT-001 (D03–D06, agreed 26 Sep 2026). They are data, so every change
creates a new policy version and an audit entry; verdicts record the version
they were evaluated with.
"""

from __future__ import annotations

import json
import sqlite3

from pydantic import BaseModel, ConfigDict, Field

from nodetrust.contracts import Mode
from nodetrust.storage import dumps, utcnow


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Mode = Mode.MONITOR
    # D03: WATCH is recorded on dashboard/CI only; e-mail only when an admin opts in.
    watch_email: bool = False
    # D04: enforce-mode actions must be pre-authorised in the policy version.
    preauthorize_gate_verified_critical: bool = False
    preauthorize_hold_large_radius: bool = False
    # D05 (option 1, agreed 26 Sep 2026): "large" radius inside one project, all thresholds inclusive.
    # A = affected versions, T = unique npm versions in the scan. Large when A >= radius_abs_threshold,
    # or when T >= radius_pct_min_total and A/T >= radius_pct_threshold. Small projects (T below the
    # minimum) use the absolute threshold alone. N=200 is an initial MVP value, not validated.
    radius_abs_threshold: int = Field(default=100, ge=1)
    radius_pct_threshold: float = Field(default=0.20, gt=0, le=1)
    radius_pct_min_total: int = Field(default=200, ge=1)
    # D06
    stale_after_hours: float = Field(default=24.0, gt=0)
    override_max_hours: float = Field(default=24.0, gt=0, le=24.0)
    # NT-025: allow generating draft pin patches (never applied automatically).
    allow_pin_suggestions: bool = False
    # Simulated incidents (demo/offline) only apply to projects that opt in, so
    # they never mix with real evidence (acceptance scenario 11).
    include_simulations: bool = False


def current_policy(con: sqlite3.Connection, project_id: str) -> tuple[int, PolicyConfig]:
    r = con.execute("SELECT version, config_json FROM policy WHERE project_id=? ORDER BY version DESC LIMIT 1",
                    (project_id,)).fetchone()
    if r is None:
        return 0, PolicyConfig()
    return r["version"], PolicyConfig.model_validate(json.loads(r["config_json"]))


def policy_version(con: sqlite3.Connection, project_id: str, version: int) -> PolicyConfig | None:
    r = con.execute("SELECT config_json FROM policy WHERE project_id=? AND version=?", (project_id, version)).fetchone()
    return PolicyConfig.model_validate(json.loads(r["config_json"])) if r else None


def save_policy(con: sqlite3.Connection, project_id: str, cfg: PolicyConfig, actor: str) -> int:
    ver, _ = current_policy(con, project_id)
    new = ver + 1
    con.execute("INSERT INTO policy(project_id, version, config_json, created_at, created_by) VALUES (?,?,?,?,?)",
                (project_id, new, dumps(cfg.model_dump(mode="json")), utcnow(), actor))
    return new
