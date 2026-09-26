"""NT-022 policy engine against the NT-001 acceptance scenarios (numbers refer to
the 'Skenario acceptance' list in NT-001)."""

import pytest

from nodetrust.contracts import DataQuality, Decision, EvidenceStatus, ExposureStatus, Mode, tier_for_score
from nodetrust.policy.config import PolicyConfig
from nodetrust.policy.engine import Finding, evaluate, exit_code_for, radius_is_large

SMALL = {"status": "KNOWN", "affected_versions": 3, "total_versions": 500, "ratio": 3 / 500}
UNKNOWN = {"status": "UNKNOWN", "affected_versions": 3, "total_versions": 0, "ratio": None}


def f(score, evidence=EvidenceStatus.UNVERIFIED, exposure=ExposureStatus.EXPOSED, radius=SMALL, sim=False):
    return Finding(incident_id="inc_1", title="t", package="p", tier=tier_for_score(score), risk_score=score,
                   evidence_status=evidence, evidence_version=1, is_simulation=sim, source="manual",
                   exposure=exposure, versions=["1.0.0"], radius=radius)


def P(**kw):
    return PolicyConfig(**kw)


ENF = dict(mode=Mode.ENFORCE)
PRE = dict(mode=Mode.ENFORCE, preauthorize_gate_verified_critical=True, preauthorize_hold_large_radius=True)


def ev(findings, policy=None, quality=DataQuality.COMPLETE, approvals=None):
    return evaluate(findings, policy=policy or P(), quality=quality, approvals=approvals)


# Scenario 1: 40/41/70/71/85/86 tiers are covered in test_ingest.test_tier_boundaries; NORMAL never implies safe:
def test_s1_normal_passes_with_explicit_non_guarantee():
    e = ev([f(40)])
    assert e.decision is Decision.PASS
    assert "not a certification" in e.findings[0].reasons[0]["message"]


# Scenario 2: WATCH default no e-mail, opt-in e-mail, build continues
def test_s2_watch_default_no_email_and_opt_in():
    e = ev([f(55)], P(**ENF))
    assert e.decision is Decision.WARN and not e.findings[0].notify and exit_code_for(e.decision) == 0
    e2 = ev([f(55)], P(watch_email=True))
    assert e2.findings[0].notify


# Scenario 3: score 90 without verified evidence never auto-gates; advisories are not compromise
def test_s3_unverified_critical_never_gates_even_preauthorized():
    e = ev([f(90)], P(**PRE))
    assert e.decision is Decision.WARN and e.findings[0].triage == "pending" and e.findings[0].notify


def test_investigate_warns_with_triage():
    e = ev([f(75)], P(**PRE))
    assert e.decision is Decision.WARN and e.findings[0].triage == "pending"


# Scenario 4: verified CRITICAL + exact exposure + small radius
def test_s4_verified_small_radius_monitor_warns_enforce_gates_only_if_preauthorized():
    v = dict(evidence=EvidenceStatus.VERIFIED)
    m = ev([f(95, **v)])
    assert m.decision is Decision.WARN and m.findings[0].recommendation.startswith("Gate recommended")
    e_no = ev([f(95, **v)], P(**ENF))
    assert e_no.decision is Decision.WARN
    e_yes = ev([f(95, **v)], P(**PRE))
    assert e_yes.decision is Decision.GATE and exit_code_for(e_yes.decision) == 1


# Scenario 5: D05 option 1 (agreed 26 Sep 2026), all thresholds inclusive:
# large when A >= 100, or T >= 200 and A/T >= 20%.
@pytest.mark.parametrize("affected,total,large", [
    (99, 1000, False), (100, 1000, True), (100, 150, True), (99, 150, False),  # absolute threshold, any T
    (39, 200, False), (40, 200, True), (79, 400, False), (80, 400, True),      # just below / exactly 20%
    (40, 199, False), (60, 199, False), (60, 200, True),                       # T = 199 / 200
    (2, 3, False),                                                             # small project, 66%
])
def test_s5_radius_thresholds(affected, total, large):
    r = {"status": "KNOWN", "affected_versions": affected, "total_versions": total, "ratio": affected / total}
    assert radius_is_large(r, P()) is large


def test_s5_empty_scan_is_not_a_valid_ratio():
    r = {"status": "KNOWN", "affected_versions": 0, "total_versions": 0, "ratio": None}
    assert radius_is_large(r, P()) is None


# Scenario 6: incomplete/truncated radius is UNKNOWN -> approval path, never "small"
def test_s6_unknown_radius_goes_to_approval_not_gate():
    v = dict(evidence=EvidenceStatus.VERIFIED, radius=UNKNOWN)
    assert radius_is_large(UNKNOWN, P()) is None
    e = ev([f(95, **v)], P(**PRE))
    assert e.decision is Decision.PENDING_APPROVAL and e.findings[0].needs_approval
    only_gate = ev([f(95, **v)], P(mode=Mode.ENFORCE, preauthorize_gate_verified_critical=True))
    assert only_gate.decision is Decision.WARN  # hold not pre-authorised -> warn + escalate
    assert ev([f(95, **v)], P(**PRE), approvals={"inc_1": "block"}).decision is Decision.GATE
    assert ev([f(95, **v)], P(**PRE), approvals={"inc_1": "allow"}).decision is Decision.WARN


def test_large_known_radius_behaves_like_unknown():
    big = {"status": "KNOWN", "affected_versions": 150, "total_versions": 400, "ratio": 150 / 400}
    assert ev([f(95, evidence=EvidenceStatus.VERIFIED, radius=big)], P(**PRE)).decision is Decision.PENDING_APPROVAL


# Scenario 7 (server side): stale/incomplete -> monitor warn UNKNOWN, enforce unavailable
@pytest.mark.parametrize("quality", [DataQuality.INCOMPLETE, DataQuality.STALE])
def test_s7_incomplete_or_stale_data(quality):
    m = ev([], P(), quality=quality)
    assert (m.decision, m.assessment) == (Decision.WARN, "unknown")
    e = ev([], P(**ENF), quality=quality)
    assert e.decision is Decision.UNAVAILABLE and exit_code_for(e.decision) == 3


def test_exposure_unknown_is_not_safe():
    e = ev([f(95, exposure=ExposureStatus.UNKNOWN)], P(**ENF))
    assert e.decision is Decision.UNAVAILABLE and e.assessment == "unknown"


def test_rejected_and_not_exposed_are_ignored():
    e = ev([f(95, evidence=EvidenceStatus.REJECTED), f(95, exposure=ExposureStatus.NOT_EXPOSED)], P(**PRE))
    assert e.decision is Decision.PASS and e.findings == []


# Scenario 11: simulations only count for projects that opt in, and are labelled
def test_s11_simulations_are_opt_in_and_labelled():
    sim = f(95, evidence=EvidenceStatus.VERIFIED, sim=True)
    assert ev([sim], P(**PRE)).findings == []
    e = ev([f(95, evidence=EvidenceStatus.VERIFIED, sim=True)], P(include_simulations=True, **PRE))
    assert e.decision is Decision.GATE and "[SIMULATION]" in e.findings[0].reasons[0]["message"]


def test_monitor_never_blocks_even_with_worst_inputs():
    e = ev([f(95, evidence=EvidenceStatus.VERIFIED, radius=UNKNOWN)], P(), quality=DataQuality.STALE)
    assert e.decision is Decision.WARN
