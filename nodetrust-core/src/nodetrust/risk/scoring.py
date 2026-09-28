"""Explainable, versioned risk scoring (NT-010).

score = clamp(round(sum of applied rule weights), 0, 100) as an int, then mapped
to a tier with `contracts.tier_for_score`. Every applied rule is returned as a
reason with its evidence. Rules live in versioned JSON files; the version is
stored with every score so old results stay interpretable after weights change.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from nodetrust.contracts import ECOSYSTEM_NPM, RiskTier, tier_for_score
from nodetrust.risk.diff import Delta
from nodetrust.storage import dumps, utcnow

DEFAULT_RULES = "rules-v1"


@dataclass(frozen=True)
class ScoreResult:
    name: str
    version: str
    score: int
    tier: RiskTier
    rules_version: str
    reasons: list[dict]
    disclaimer: str

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "score": self.score, "tier": self.tier.value,
                "rules_version": self.rules_version, "reasons": self.reasons, "disclaimer": self.disclaimer,
                "score_kind": "heuristic"}


@lru_cache(maxsize=8)
def load_rules(version: str = DEFAULT_RULES) -> dict:
    text = resources.files("nodetrust.risk").joinpath("rules", f"{version}.json").read_text(encoding="utf-8")
    rules = json.loads(text)
    if rules.get("version") != version:
        raise ValueError(f"rules file {version} declares version {rules.get('version')!r}")
    ids = [r["id"] for r in rules["rules"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    return rules


def _signals(delta: Delta) -> dict[str, tuple[int, object]]:
    """rule id -> (count, evidence). count 0 = not triggered."""
    all_replaced = (delta.maintainers_retained == 0 and bool(delta.maintainers_removed)
                    and bool(delta.maintainers_added))
    return {
        "same_version_integrity_changed": (int(delta.same_version_integrity_changed),
                                           delta.same_version_integrity_values),
        "install_script_added": (int(bool(delta.install_scripts_added)), delta.install_scripts_added),
        "all_maintainers_replaced": (int(all_replaced),
                                     {"removed": delta.maintainers_removed, "added": delta.maintainers_added}),
        "publisher_new_to_package": (int(delta.publisher_new_to_package),
                                     {"publisher": delta.publisher, "previous": delta.base_publisher}),
        "dependency_on_new_package": (len(delta.new_dependency_targets), delta.new_dependency_targets),
        "repository_changed": (int(delta.repository_changed is not None), delta.repository_changed),
        "maintainer_added": (len(delta.maintainers_added), delta.maintainers_added),
        "dependency_added": (len(delta.deps_added), delta.deps_added),
    }


def score_delta(delta: Delta, *, rules_version: str = DEFAULT_RULES) -> ScoreResult:
    rules = load_rules(rules_version)
    sig = _signals(delta)
    total = 0
    reasons = []
    for rule in rules["rules"]:
        count, evidence = sig.get(rule["id"], (0, None))
        if not count:
            continue
        w = rule["weight"] * count if rule.get("per_item") else rule["weight"]
        if rule.get("cap") is not None:
            w = min(w, rule["cap"])
        total += w
        reasons.append({"rule": rule["id"], "weight": w, "count": count, "evidence": evidence,
                        "description": rule["description"]})
    if delta.unknown_dependency_targets:
        reasons.append({"rule": "dependency_target_not_assessed", "weight": 0,
                        "count": len(delta.unknown_dependency_targets),
                        "evidence": delta.unknown_dependency_targets,
                        "description": "Added dependency not in graph yet; age not assessed (not treated as safe)."})
    score = max(0, min(100, int(round(total))))
    return ScoreResult(delta.name, delta.version, score, tier_for_score(score), rules_version, reasons,
                       rules["disclaimer"])


def score_and_store(con: sqlite3.Connection, delta: Delta, rules_version: str = DEFAULT_RULES) -> ScoreResult:
    res = score_delta(delta, rules_version=rules_version)
    con.execute(
        "INSERT INTO risk_score(ecosystem, name, version, score, tier, rules_version, reasons_json, computed_at) "
        "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(ecosystem, name, version, rules_version) DO UPDATE SET "
        "score=excluded.score, tier=excluded.tier, reasons_json=excluded.reasons_json, computed_at=excluded.computed_at",
        (ECOSYSTEM_NPM, res.name, res.version, res.score, res.tier.value, res.rules_version, dumps(res.reasons),
         utcnow()))
    return res


def latest_score(con: sqlite3.Connection, name: str, version: str,
                 rules_version: str = DEFAULT_RULES) -> dict | None:
    r = con.execute("SELECT score, tier, rules_version, reasons_json, computed_at FROM risk_score "
                    "WHERE ecosystem=? AND name=? AND version=? AND rules_version=?",
                    (ECOSYSTEM_NPM, name, version, rules_version)).fetchone()
    if not r:
        return None
    return {"score": r["score"], "tier": r["tier"], "rules_version": r["rules_version"],
            "reasons": json.loads(r["reasons_json"]), "computed_at": r["computed_at"]}
