"""nodetrust-ci entry point.

    python cli.py sbom   --lockfile package-lock.json --out sbom.json
    python cli.py submit [--sbom syft.json] --lockfile package-lock.json --mode monitor|enforce

The API key is read from the NODETRUST_API_KEY environment variable only (never
from argv, which can leak into process listings and logs).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

if __package__ in (None, ""):  # executed as a script from the action
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nodetrust_ci import EXIT_BLOCKED, EXIT_CONFIG, EXIT_OK, EXIT_UNAVAILABLE, SCHEMA_VERSION  # noqa: E402
from nodetrust_ci.client import ApiConfigError, ApiUnavailable, submit  # noqa: E402
from nodetrust_ci.lockfile import LockfileError, sbom_from_lockfile  # noqa: E402
from nodetrust_ci.sbom import enrich, has_root_relations, minimize  # noqa: E402
from nodetrust_ci.summary import annotation, render_summary, render_unavailable  # noqa: E402

DECISION_EXIT = {"pass": EXIT_OK, "warn": EXIT_OK, "gate": EXIT_BLOCKED, "pending_approval": EXIT_BLOCKED,
                 "unavailable": EXIT_UNAVAILABLE}


def _out(line: str) -> None:
    print(line, flush=True)


def _append(path: str | None, text: str) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)


def _set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")


def build_sbom(args) -> tuple[dict, list[str]]:
    notes: list[str] = []
    lock_sbom = None
    if args.lockfile and Path(args.lockfile).exists():
        lock_sbom, warns = sbom_from_lockfile(Path(args.lockfile), include_dev=not args.no_dev)
        notes += warns
    if args.sbom:
        try:
            gen = json.loads(Path(args.sbom).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise LockfileError(f"cannot read SBOM {args.sbom}: {e}") from e
        if not has_root_relations(gen):
            if lock_sbom is None:
                notes.append("generator SBOM has no dependency relations and no lockfile was found: "
                             "paths and blast radius will be UNKNOWN")
            else:
                gen, extra = enrich(gen, lock_sbom)
                notes.append("dependency relations taken from package-lock.json")
                notes += extra[:20]
        return minimize(gen), notes
    if lock_sbom is None:
        raise LockfileError(f"no SBOM given and {args.lockfile} not found")
    return minimize(lock_sbom), notes


def cmd_sbom(args) -> int:
    try:
        sbom, notes = build_sbom(args)
    except LockfileError as e:
        _out(annotation("error", str(e)))
        return EXIT_CONFIG
    Path(args.out).write_text(json.dumps(sbom, indent=1), encoding="utf-8")
    for n in notes:
        _out(annotation("notice", n))
    _out(f"wrote {args.out}: {len(sbom['components'])} components, {len(sbom['dependencies'])} relation groups")
    return EXIT_OK


def cmd_submit(args) -> int:
    mode = args.mode
    key = os.environ.get("NODETRUST_API_KEY", "").strip()
    if key and os.environ.get("GITHUB_ACTIONS") == "true":
        _out(f"::add-mask::{key}")
    missing = [n for n, v in (("api-url", args.api_url), ("project-id", args.project), ("NODETRUST_API_KEY", key),
                              ("commit", args.commit), ("branch", args.branch)) if not v]
    if missing:
        msg = f"missing configuration: {', '.join(missing)}"
        if "NODETRUST_API_KEY" in missing and os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
            msg += " (secrets are not available to pull requests from forks; see README 'Untrusted PRs')"
        _out(annotation("error", msg))
        _set_output("decision", "error")
        return EXIT_CONFIG
    try:
        sbom, notes = build_sbom(args)
    except LockfileError as e:
        _out(annotation("error", str(e)))
        _set_output("decision", "error")
        return EXIT_CONFIG
    for n in notes[:20]:
        _out(annotation("notice", n))
    payload = {"commit": args.commit, "branch": args.branch, "run_id": args.run_id, "sbom": sbom}
    try:
        v = submit(args.api_url, args.project, key, payload, budget_s=args.timeout)
    except ApiConfigError as e:
        _out(annotation("error", f"NodeTrust rejected the request: {e}"))
        if e.details:
            _out(json.dumps(e.details)[:2000])
        _set_output("decision", "error")
        return EXIT_CONFIG
    except ApiUnavailable as e:
        _append(args.summary, render_unavailable(mode, str(e)))
        _set_output("decision", "unavailable")
        if mode == "enforce":
            _out(annotation("error", f"Assessment unavailable (enforce mode fails closed): {e}"))
            return EXIT_UNAVAILABLE
        _out(annotation("warning", f"Assessment UNKNOWN (monitor mode continues): {e}"))
        return EXIT_OK

    if v.get("schema_version") != SCHEMA_VERSION:
        _out(annotation("warning", f"server contract {v.get('schema_version')} differs from client {SCHEMA_VERSION}"))
    if v.get("mode") != mode:
        _out(annotation("warning", f"action input mode={mode} but project policy mode={v.get('mode')}; "
                                   f"the server's policy decides the verdict"))
    if args.out:
        Path(args.out).write_text(json.dumps(v, indent=1), encoding="utf-8")
    _append(args.summary, render_summary(v, dashboard_url=f"{args.api_url.rstrip('/')}/dashboard/"))
    decision = v["decision"]
    code = DECISION_EXIT.get(decision, EXIT_CONFIG)
    level = {EXIT_OK: "warning" if decision == "warn" else "notice"}.get(code, "error")
    top = "; ".join(r["message"] for r in (v.get("reasons") or [])[:2]) or "no findings"
    _out(annotation(level, f"decision={decision} assessment={v['assessment']}: {top}"))
    _set_output("decision", decision)
    _set_output("exit-code", str(code))
    return code


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="nodetrust-ci")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("sbom", "submit"):
        sp = sub.add_parser(name)
        sp.add_argument("--lockfile", default="package-lock.json")
        sp.add_argument("--sbom", help="generator SBOM (e.g. Syft CycloneDX JSON); relations filled from lockfile")
        sp.add_argument("--no-dev", action="store_true", help="exclude dev-only packages")
        if name == "sbom":
            sp.add_argument("--out", required=True)
    s = sub.choices["submit"]
    env = os.environ.get
    s.add_argument("--api-url", default=env("NODETRUST_API_URL"))
    s.add_argument("--project", default=env("NODETRUST_PROJECT_ID"))
    s.add_argument("--mode", choices=("monitor", "enforce"), default=env("NODETRUST_MODE") or "monitor")
    s.add_argument("--commit", default=env("GITHUB_SHA"))
    s.add_argument("--branch", default=env("GITHUB_HEAD_REF") or env("GITHUB_REF_NAME"))
    default_run = f"{env('GITHUB_RUN_ID')}.{env('GITHUB_RUN_ATTEMPT') or '1'}" if env("GITHUB_RUN_ID") else None
    s.add_argument("--run-id", default=default_run)
    s.add_argument("--timeout", type=float, default=float(env("NODETRUST_TIMEOUT") or 60))
    s.add_argument("--summary", default=env("GITHUB_STEP_SUMMARY"))
    s.add_argument("--out", default=env("NODETRUST_VERDICT_PATH"))
    args = p.parse_args(argv)
    return cmd_sbom(args) if args.cmd == "sbom" else cmd_submit(args)


if __name__ == "__main__":
    raise SystemExit(main())
