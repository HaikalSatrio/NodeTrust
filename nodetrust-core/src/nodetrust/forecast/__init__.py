"""Propagation forecast: HEURISTIC STAND-IN for NT-015 (owner: Haikal).

Exists only so that alerts (NT-023) and the dashboard (NT-026) have a timeline
field to carry and display. It is not the forecasting engine, it is not
validated (NT-014/016 own that), and every output says so:
kind = "heuristic_simulation", validated = False.

Model: dependents found by reverse BFS are grouped by hop. The time for hop h to
be reached is  base_interval * ecosystem_factor * hop_growth^(h-1) / (1 + m * c),
where c is the seed's normalised betweenness. Horizons report how many known
dependents fall inside each window. The low/high band is a fixed x0.5 / x2
multiplier: a heuristic range, not a statistical confidence interval.
"""

from __future__ import annotations

PARAMS = {
    "version": "forecast-heuristic-v0",
    "base_interval_hours": 6.0,
    "ecosystem_factor": {"npm": 1.0},
    "hop_growth": 1.6,
    "centrality_multiplier": 0.5,
    "band": [0.5, 2.0],
}
HORIZONS_H = [1, 6, 12, 24, 48, 72]


def forecast(by_hop: dict[int, int], *, centrality: float | None, ecosystem: str = "npm",
             truncated: bool = False, params: dict = PARAMS) -> dict:
    base = {"kind": "heuristic_simulation", "validated": False, "params_version": params["version"],
            "label": "Heuristic simulation - not a validated forecast; ranges are not confidence intervals.",
            "horizons": []}
    if not by_hop:
        return {**base, "status": "unknown", "reason": "no dependents known in the registry graph"}
    c = centrality or 0.0
    factor = params["ecosystem_factor"].get(ecosystem)
    if factor is None:
        return {**base, "status": "unknown", "reason": f"no ecosystem factor for {ecosystem} (not validated)"}
    lo_m, hi_m = params["band"]
    hop_t = {h: params["base_interval_hours"] * factor * params["hop_growth"] ** (h - 1) /
             (1 + params["centrality_multiplier"] * c) for h in by_hop}
    for H in HORIZONS_H:
        base["horizons"].append({
            "hours": H,
            "expected": sum(n for h, n in by_hop.items() if hop_t[h] <= H),
            "low": sum(n for h, n in by_hop.items() if hop_t[h] * hi_m <= H),
            "high": sum(n for h, n in by_hop.items() if hop_t[h] * lo_m <= H),
        })
    base["status"] = "ok"
    base["hop_hours"] = {str(h): round(t, 2) for h, t in sorted(hop_t.items())}
    base["assumptions"] = ["counts only dependents already in the local graph",
                           "declared specs admitting the version are treated as potential adopters"]
    if truncated:
        base["assumptions"].append("blast radius was truncated; counts are lower bounds")
    return base
