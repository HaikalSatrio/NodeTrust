"""Human output: GitHub step summary (Markdown) and workflow annotations."""

from __future__ import annotations


def _esc_md(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def annotation(level: str, message: str, title: str = "NodeTrust") -> str:
    """GitHub workflow command, with the escaping GitHub requires for data/properties."""
    def data(v: str) -> str:
        return v.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def prop(v: str) -> str:
        return data(v).replace(":", "%3A").replace(",", "%2C")

    return f"::{level} title={prop(title)}::{data(message)}"


ICON = {"pass": "✅", "warn": "⚠️", "gate": "⛔", "pending_approval": "⏸️", "unavailable": "❔"}


def render_summary(v: dict, *, dashboard_url: str | None = None) -> str:
    lines = [f"## NodeTrust: {ICON.get(v['decision'], '')} `{v['decision']}`", ""]
    labels = v.get("labels") or []
    if "simulation" in labels:
        lines.append("> **SIMULATION**: this verdict includes simulated incidents (demo data).")
    if "offline_snapshot" in labels:
        lines.append("> **Offline snapshot**: not a live assessment.")
    lines += [
        f"- Mode: `{v['mode']}` · policy v{v['policy_version']} · assessment: `{v['assessment']}`",
        f"- Data quality: `{v['data_quality']['status']}` · graph `{v['data_quality'].get('graph_snapshot')}`",
        f"- Scan: `{v['scan']['commit'][:12]}` on `{v['scan']['branch']}` (scan `{v['scan']['scan_id']}`"
        f"{', reused' if v.get('scan_reused') else ''})",
    ]
    drift = v.get("drift")
    if drift and not drift.get("first_scan"):
        lines.append(f"- Drift vs previous scan: +{drift['added']} / -{drift['removed']} / ~{drift['changed']}")
    if v.get("override"):
        o = v["override"]
        lines.append(f"- Override `{o['id']}` by {o['by']}: {_esc_md(o['reason'])} "
                     f"(original decision `{o['original_decision']}`)")
    lines.append("")
    findings = v.get("findings") or []
    if findings:
        lines += ["| Package | Tier | Evidence | Exposure | Decision | Path |", "|---|---|---|---|---|---|"]
        for f in findings:
            path = " → ".join(f["paths"][0]) if f.get("paths") else "unknown"
            sim = " (simulation)" if f.get("is_simulation") else ""
            lines.append(f"| `{f['package']}@{', '.join(f['versions'])}`{sim} | {f['tier']} ({f['risk_score']}, heuristic) "
                         f"| {f['evidence_status']} | {f['exposure']} | `{f['decision']}` | {_esc_md(path)} |")
        lines.append("")
    reasons = [r["message"] for r in v.get("reasons") or []] + \
        [r["message"] for f in findings for r in f.get("reasons") or []]
    if reasons:
        lines += ["**Why**", ""] + [f"- {_esc_md(r)}" for r in reasons] + [""]
    if v.get("approvals_pending"):
        lines.append(f"Approval required from a project admin: {', '.join(v['approvals_pending'])}")
    lines.append("_Scores are heuristic, not probabilities. Advisories are not evidence of compromise. "
                 "Unknown packages are not safe._")
    if dashboard_url:
        lines.append(f"\n[Open the NodeTrust dashboard]({dashboard_url})")
    return "\n".join(lines) + "\n"


def render_unavailable(mode: str, reason: str) -> str:
    verdict = "failing this step (enforce mode)" if mode == "enforce" else "continuing (monitor mode)"
    return (f"## NodeTrust: {ICON['unavailable']} assessment unavailable\n\n"
            f"No verdict could be obtained: {_esc_md(reason)}.\n\n"
            f"Assessment is **UNKNOWN**: this is not a pass and not a compromise verdict; {verdict}.\n")
