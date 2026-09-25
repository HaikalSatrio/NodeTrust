"""Policy evaluation (NT-022): the D04 matrix as code.

`evaluate` is pure: findings + data quality + policy + prior approval decisions
in, decision + reasons out. Storage, overrides and notifications are handled by
the scan pipeline around it.

Evaluation order (NT-001 D04): identity/config (API layer) -> data quality and
freshness -> exact exposure -> tier and evidence status -> radius -> mode,
pre-authorisation and approval -> verdict with reasons.

Monitor mode never blocks: it only returns pass or warn.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nodetrust.contracts import DataQuality, Decision, EvidenceStatus, ExposureStatus, Mode, RiskTier
from nodetrust.policy.config import PolicyConfig

SEVERITY = {Decision.PASS: 0, Decision.WARN: 1, Decision.UNAVAILABLE: 2, Decision.PENDING_APPROVAL: 3,
            Decision.GATE: 4}


def worst(decisions) -> Decision:
    return max(decisions, key=lambda d: SEVERITY[d], default=Decision.PASS)


def exit_code_for(decision: Decision) -> int:
    """CI contract: 0 pass/warn, 1 gate or held for approval, 3 assessment unavailable.
    (2 is reserved for configuration/auth/payload errors, raised client-side.)"""
    return {Decision.PASS: 0, Decision.WARN: 0, Decision.GATE: 1, Decision.PENDING_APPROVAL: 1,
            Decision.UNAVAILABLE: 3}[decision]


@dataclass
class Finding:
    incident_id: str
    title: str
    package: str
    tier: RiskTier
    risk_score: int
    evidence_status: EvidenceStatus
    evidence_version: int
    is_simulation: bool
    source: str
    exposure: ExposureStatus
    versions: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    paths: list[list[str]] = field(default_factory=list)
    radius: dict = field(default_factory=dict)
    # filled by evaluate()
    decision: Decision = Decision.PASS
    reasons: list[dict] = field(default_factory=list)
    notify: bool = False
    triage: str | None = None  # "pending" when a human must look
    needs_approval: bool = False
    recommendation: str | None = None

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id, "title": self.title, "package": self.package,
            "versions": self.versions, "tier": self.tier.value, "risk_score": self.risk_score,
            "score_kind": "heuristic", "evidence_status": self.evidence_status.value,
            "evidence_version": self.evidence_version, "is_simulation": self.is_simulation, "source": self.source,
            "exposure": self.exposure.value, "paths": self.paths, "radius": self.radius,
            "decision": self.decision.value, "reasons": self.reasons, "notify": self.notify, "triage": self.triage,
            "needs_approval": self.needs_approval, "recommendation": self.recommendation,
        }


@dataclass
class Evaluation:
    decision: Decision
    assessment: str  # "ok" | "unknown"
    findings: list[Finding]
    reasons: list[dict]


def radius_is_large(radius: dict, policy: PolicyConfig) -> bool | None:
    """True/False for a known radius, None when UNKNOWN (treated like large, D05)."""
    if radius.get("status") != "KNOWN":
        return None
    return (radius["affected_versions"] >= policy.radius_abs_threshold
            or radius["ratio"] >= policy.radius_pct_threshold)


def _r(code: str, message: str, **extra) -> dict:
    return {"code": code, "message": message, **extra}


def evaluate(findings: list[Finding], *, policy: PolicyConfig, quality: DataQuality,
             approvals: dict[str, str] | None = None) -> Evaluation:
    """approvals: incident_id -> 'pending' | 'block' | 'allow' for this scan."""
    approvals = approvals or {}
    enforce = policy.mode is Mode.ENFORCE
    global_reasons: list[dict] = []
    decisions = [Decision.PASS]
    assessment = "ok"

    # 1) data quality / freshness
    if quality is not DataQuality.COMPLETE:
        assessment = "unknown"
        msg = ("scan coverage is incomplete (missing dependency relations or inexact versions)"
               if quality is DataQuality.INCOMPLETE else "required data is stale")
        global_reasons.append(_r(f"data_{quality.value}", f"Assessment UNKNOWN: {msg}."))
        decisions.append(Decision.UNAVAILABLE if enforce else Decision.WARN)

    kept: list[Finding] = []
    for f in findings:
        if f.evidence_status is EvidenceStatus.REJECTED or f.exposure is ExposureStatus.NOT_EXPOSED:
            continue
        if f.is_simulation and not policy.include_simulations:
            continue
        kept.append(f)
        sim = " [SIMULATION]" if f.is_simulation else ""

        # 2) exact exposure
        if f.exposure is ExposureStatus.UNKNOWN:
            assessment = "unknown"
            f.decision = Decision.UNAVAILABLE if enforce else Decision.WARN
            f.reasons.append(_r("exposure_unknown", f"{f.package} is present but its exact version could not be "
                                                    f"matched; exposure UNKNOWN (not assumed safe).{sim}"))
            decisions.append(f.decision)
            continue

        # 3) tier and evidence status
        if f.tier is RiskTier.NORMAL:
            f.decision = Decision.PASS
            f.reasons.append(_r("tier_normal", f"{f.package}: NORMAL tier (heuristic score {f.risk_score}); "
                                               f"not a certification of safety.{sim}"))
        elif f.tier is RiskTier.WATCH:
            f.decision = Decision.WARN
            f.notify = policy.watch_email
            f.reasons.append(_r("tier_watch", f"{f.package}: WATCH (score {f.risk_score}). Recorded; "
                                              f"{'e-mail enabled by policy' if f.notify else 'no e-mail by default'}.{sim}"))
        elif f.tier is RiskTier.INVESTIGATE:
            f.decision, f.notify, f.triage = Decision.WARN, True, "pending"
            f.reasons.append(_r("tier_investigate", f"{f.package}: INVESTIGATE (score {f.risk_score}). "
                                                    f"Triage pending; scores alone never gate.{sim}"))
        elif f.evidence_status is not EvidenceStatus.VERIFIED:
            f.decision, f.notify, f.triage = Decision.WARN, True, "pending"
            f.reasons.append(_r("critical_unverified", f"{f.package}: CRITICAL score {f.risk_score} but evidence is "
                                                       f"not verified by a human; no automatic gate.{sim}"))
            f.recommendation = "Verify source, affected versions and exposure before any blocking action."
        else:
            # verified CRITICAL with exact exposure: 4) radius, 5) mode/pre-authorisation/approval
            f.notify = True
            large = radius_is_large(f.radius, policy)
            fresh = quality is DataQuality.COMPLETE
            if large is False and fresh:
                if enforce and policy.preauthorize_gate_verified_critical:
                    f.decision = Decision.GATE
                    f.reasons.append(_r("gate_preauthorized", f"{f.package}: verified compromise, exact version "
                                                              f"exposed, small radius; gate pre-authorised in policy.{sim}"))
                else:
                    f.decision = Decision.WARN
                    f.recommendation = "Gate recommended: verified compromise with exact exposure."
                    f.reasons.append(_r("gate_recommended", f"{f.package}: verified compromise; gate recommended "
                                        f"({'monitor mode' if not enforce else 'gate not pre-authorised'}).{sim}"))
            else:
                why = "radius UNKNOWN" if large is None else "large radius"
                if not fresh:
                    why += " / data not fresh"
                prior = approvals.get(f.incident_id)
                if enforce and policy.preauthorize_hold_large_radius:
                    f.needs_approval = True
                    if prior == "block":
                        f.decision = Decision.GATE
                        f.reasons.append(_r("approval_block", f"{f.package}: approver decided to block ({why}).{sim}"))
                    elif prior == "allow":
                        f.decision = Decision.WARN
                        f.reasons.append(_r("approval_allow", f"{f.package}: approver allowed the build ({why}).{sim}"))
                    else:
                        f.decision = Decision.PENDING_APPROVAL
                        f.reasons.append(_r("hold_pending_approval", f"{f.package}: verified compromise with {why}; "
                                            f"build held pending approval for this incident and project.{sim}"))
                else:
                    f.decision = Decision.WARN
                    f.reasons.append(_r("escalate", f"{f.package}: verified compromise with {why}; escalated. "
                                        f"No bulk action is taken.{sim}"))
                f.recommendation = "Escalate to the project owner; decide per incident. No bulk remediation."
        decisions.append(f.decision)

    decision = worst(decisions)
    if not enforce:  # monitor never blocks
        decision = Decision.WARN if decision is not Decision.PASS else Decision.PASS
    if not kept and quality is DataQuality.COMPLETE:
        global_reasons.append(_r("no_exposure", "No known incident matches an exact version in this scan. "
                                                "This is not a certification of safety."))
    return Evaluation(decision, assessment, kept, global_reasons)
