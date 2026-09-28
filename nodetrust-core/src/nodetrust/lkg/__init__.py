"""Last-known-good versions and draft pin patches (NT-025, limited per NT-001 D01).

LKG candidate for package P in project X = the most recent exact version of P
that appeared in an earlier scan of X whose verdict passed (pass/warn), that is
not one of the bad versions, and that is re-checked *now* against current
evidence (no non-rejected incident and no malicious-package report affects it).
No candidate -> no pin. We never invent a version.

The patch is a draft: an npm `overrides` entry in package.json (npm >= 8.3) plus
its reverse patch. It is only produced when the project policy allows it and a
project admin asks; it is never committed, pushed or applied by NodeTrust. The
lockfile must be regenerated and reviewed by a human; `verify_pin` checks the
next scan actually resolves to the pinned version.
"""

from __future__ import annotations

import difflib
import json
import re
import sqlite3

from nodetrust.incidents import affects, list_incidents
from nodetrust.intel.osv import advisories_for
from nodetrust.semver import parse_version
from nodetrust.storage import utcnow


def _still_clean(con: sqlite3.Connection, name: str, version: str, include_simulations: bool) -> tuple[bool, list, list]:
    blocking, vulns = [], []
    for inc in list_incidents(con, name=name):
        if inc["is_simulation"] and not include_simulations:
            continue
        if affects(inc["affected"], version):
            blocking.append({"incident_id": inc["id"], "title": inc["title"], "evidence": inc["evidence_status"]})
    for adv in advisories_for(con, name, version):
        if adv["kind"] == "malicious_report":
            blocking.append({"advisory": adv["ids"], "kind": adv["kind"]})
        else:
            vulns.append({"ids": adv["ids"], "summary": adv["summary"]})
    return not blocking, blocking, vulns


def find_lkg(con: sqlite3.Connection, *, project_id: str, name: str, bad_versions: set[str],
             include_simulations: bool = False) -> dict:
    rows = con.execute(
        "SELECT sc.version, s.id AS scan_id, s.commit_sha, s.branch, s.received_at, "
        "(SELECT v.decision FROM verdict v WHERE v.scan_id = s.id ORDER BY v.created_at DESC, v.rowid DESC LIMIT 1) "
        "AS decision FROM scan_component sc JOIN scan s ON s.id = sc.scan_id "
        "WHERE s.project_id=? AND sc.ecosystem='npm' AND sc.name=? AND sc.status='exact' "
        "ORDER BY s.received_at DESC, s.rowid DESC", (project_id, name)).fetchall()
    rejected: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        v = r["version"]
        if v in bad_versions or v in seen:
            continue
        seen.add(v)
        if r["decision"] not in ("pass", "warn"):
            rejected.append({"version": v, "why": f"scan {r['scan_id']} verdict was {r['decision']}"})
            continue
        ok, blocking, vulns = _still_clean(con, name, v, include_simulations)
        if not ok:
            rejected.append({"version": v, "why": "affected by current evidence", "evidence": blocking})
            continue
        return {"available": True, "name": name, "version": v, "rechecked_at": utcnow(),
                "provenance": {"scan_id": r["scan_id"], "commit": r["commit_sha"], "branch": r["branch"],
                               "received_at": r["received_at"], "verdict_decision": r["decision"]},
                "known_vulnerabilities": vulns, "rejected_candidates": rejected}
    return {"available": False, "name": name, "rechecked_at": utcnow(), "rejected_candidates": rejected,
            "message": "No last-known-good version satisfies the rules; no pin is suggested."}


def _indent_of(text: str) -> int:
    m = re.search(r"^\{\s*\n([ \t]+)\"", text, re.M)
    return len(m.group(1).expandtabs(2)) if m else 2


def pin_patch(package_json_text: str, name: str, version: str) -> dict:
    parse_version(version)  # exact versions only
    try:
        data = json.loads(package_json_text)
    except ValueError as e:
        raise ValueError(f"package.json is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("package.json must be a JSON object")
    overrides = data.get("overrides") if isinstance(data.get("overrides"), dict) else {}
    previous = overrides.get(name)
    new = dict(data)
    new["overrides"] = {**overrides, name: version}
    indent = _indent_of(package_json_text)
    new_text = json.dumps(new, indent=indent, ensure_ascii=False) + "\n"
    orig_lines = package_json_text.splitlines(keepends=True)
    if orig_lines and not orig_lines[-1].endswith("\n"):
        orig_lines[-1] += "\n"
    new_lines = new_text.splitlines(keepends=True)
    return {
        "patch": "".join(difflib.unified_diff(orig_lines, new_lines, "a/package.json", "b/package.json")),
        "reverse_patch": "".join(difflib.unified_diff(new_lines, orig_lines, "a/package.json", "b/package.json")),
        "replaces_existing_override": previous,
        "applies_automatically": False,
        "instructions": [
            "Review the patch; it adds an npm 'overrides' entry (requires npm >= 8.3).",
            "Apply it on a branch and run `npm install` to regenerate package-lock.json.",
            f"Check the lockfile resolves every {name} entry to {version}; do not hand-edit the lockfile.",
            "Open a pull request through your normal review. NodeTrust never commits or pushes.",
            "To undo, apply the reverse patch and regenerate the lockfile.",
        ],
    }


def verify_pin(con: sqlite3.Connection, *, project_id: str, scan_id: str, name: str, version: str) -> dict:
    rows = con.execute("SELECT sc.version FROM scan_component sc JOIN scan s ON s.id=sc.scan_id "
                       "WHERE s.id=? AND s.project_id=? AND sc.name=? AND sc.ecosystem='npm'",
                       (scan_id, project_id, name)).fetchall()
    found = sorted({r["version"] or "?" for r in rows})
    return {"scan_id": scan_id, "package": name, "expected": version, "found": found,
            "consistent": found == [version]}
