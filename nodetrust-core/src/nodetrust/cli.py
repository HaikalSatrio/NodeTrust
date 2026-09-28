"""`nodetrust` command line: serve, worker, ingestion, intel import, ops.

Everything that touches the network goes through the gated transport; with the
default NODETRUST_ALLOW_NETWORK=false those commands stop with a clear message.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from nodetrust.config import Settings
from nodetrust.obs import configure_logging, get_logger, log
from nodetrust.storage import Database

_log = get_logger("cli")


def _db(s: Settings) -> Database:
    return Database(s.db_path)


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_serve(s: Settings, a) -> int:
    import uvicorn

    from nodetrust.api.app import create_app

    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.i_know_this_is_exposed:
        print("Refusing to bind to a non-loopback address without --i-know-this-is-exposed "
              "(put a TLS reverse proxy in front).", file=sys.stderr)
        return 2
    proxy = {"proxy_headers": True, "forwarded_allow_ips": s.forwarded_allow_ips} if s.forwarded_allow_ips         else {"proxy_headers": False}
    uvicorn.run(create_app(s), host=a.host, port=a.port, log_config=None, access_log=False, **proxy)
    return 0


def cmd_worker(s: Settings, a) -> int:
    from nodetrust.alerts import OutboxSender, SmtpSender, dispatch_pending
    from nodetrust.registry.feed import ChangesFeed
    from nodetrust.registry.fetch import Fetcher
    from nodetrust.registry.transport import NetworkDisabled, RateLimiter, TransportError, make_transport

    db = _db(s)
    transport = make_transport(s.allow_network)
    feed = ChangesFeed(db, transport, s.npm_changes_url, timeout=s.http_timeout_s)
    fetcher = Fetcher(db, transport, s.npm_registry_url, timeout=s.http_timeout_s, max_bytes=s.max_packument_bytes,
                      limiter=RateLimiter(s.fetch_rate_per_s))
    if s.smtp_host:
        import ssl

        sender = SmtpSender(s.smtp_host, s.smtp_port, s.smtp_user,
                            s.smtp_password.get_secret_value() if s.smtp_password else None, s.smtp_from,
                            allow_network=s.allow_network,
                            ssl_context=ssl.create_default_context(cafile=s.smtp_ca_file) if s.smtp_ca_file else None)
    else:
        sender = OutboxSender(s.alert_outbox_dir, s.smtp_from)
    while True:
        if s.allow_network:
            try:
                feed.poll_once()
            except (TransportError, ValueError) as e:
                log(_log, logging.WARNING, "worker.feed_error", error=str(e))
            try:
                fetcher.process_pending(limit=200)
            except NetworkDisabled:
                pass
        rep = dispatch_pending(db, sender, max_attempts=s.alert_max_attempts)
        log(_log, logging.INFO, "worker.tick", network=s.allow_network, **rep)
        if a.once:
            return 0
        time.sleep(a.interval)


def cmd_ingest(s: Settings, a) -> int:
    """Offline: load packument JSON files (one per package) into the graph."""
    from nodetrust.graph.store import upsert_packument
    from nodetrust.incidents import upsert_crawler_signal
    from nodetrust.registry.normalize import InvalidPackument, normalize_packument
    from nodetrust.risk.diff import diff_versions
    from nodetrust.risk.scoring import score_and_store

    db = _db(s)
    done, errors = 0, []
    for p in sorted(Path(a.path).glob("*.json")):
        try:
            rec = normalize_packument(json.loads(p.read_text(encoding="utf-8")))
        except (ValueError, InvalidPackument) as e:
            errors.append(f"{p.name}: {e}")
            continue
        with db.transaction() as con:
            res = upsert_packument(con, rec, source=f"file:{p.name}")
            todo = sorted(set(res.new_versions) | {x for x, _, _ in res.integrity_changes})
            for delta in diff_versions(con, rec.name, todo):
                score = score_and_store(con, delta)
                if a.signals:
                    upsert_crawler_signal(con, score)
        done += 1
    _print({"ingested": done, "errors": errors})
    return 1 if errors and not done else 0


def cmd_osv(s: Settings, a) -> int:
    from nodetrust.intel.osv import import_records, iter_dir, iter_zip

    p = Path(a.path)
    docs = iter_zip(p) if p.suffix == ".zip" else iter_dir(p)
    rep = import_records(_db(s), docs, source=f"osv-file:{p.name}")
    _print(rep.__dict__)
    return 0


def cmd_centrality(s: Settings, a) -> int:
    from nodetrust.graph.centrality import compute_and_cache

    db = _db(s)
    with db.transaction() as con:
        _print(compute_and_cache(con))
    return 0


def cmd_dispatch(s: Settings, a) -> int:
    from nodetrust.alerts import OutboxSender, dispatch_pending

    _print(dispatch_pending(_db(s), OutboxSender(s.alert_outbox_dir, s.smtp_from), max_attempts=s.alert_max_attempts))
    return 0


def cmd_project(s: Settings, a) -> int:
    from nodetrust.api.auth import create_project
    from nodetrust.policy.config import PolicyConfig, save_policy

    db = _db(s)
    with db.transaction() as con:
        proj, key = create_project(con, name=a.name, alert_email=a.email, created_by="cli")
        save_policy(con, proj["id"], PolicyConfig(), "cli")
        db.audit(con, actor="cli", action="project.created", project_id=proj["id"], target=proj["id"])
    _print({"project": proj, "admin_key": key, "note": "Store the admin key now; it is not shown again."})
    return 0


def cmd_backup(s: Settings, a) -> int:
    from nodetrust.ops import backup

    _print(backup(Path(s.db_path), Path(a.out)))
    return 0


def cmd_restore(s: Settings, a) -> int:
    from nodetrust.ops import restore, verify_backup

    if a.verify_only:
        _print(verify_backup(Path(a.backup)))
        return 0
    if not a.yes:
        print("Restore replaces the database. Stop the API and worker, then re-run with --yes.", file=sys.stderr)
        return 2
    _print(restore(Path(a.backup), Path(s.db_path)))
    return 0


def cmd_purge(s: Settings, a) -> int:
    from nodetrust.ops import purge

    db = _db(s)
    with db.transaction() as con:
        res = purge(con, days=a.days or s.retention_days, outbox=s.alert_outbox_dir)
        db.audit(con, actor="cli", action="retention.purge", detail=res)
    _print(res)
    return 0


def _default_demo_fixtures() -> Path:
    # A source checkout keeps them at <repo>/fixtures/demo. An installed package (pip install ., the
    # Docker image) has no repo around it, so fall back to ./fixtures/demo (the image's WORKDIR).
    for base in (Path(__file__).resolve().parents[2], Path.cwd()):
        if (base / "fixtures" / "demo").is_dir():
            return base / "fixtures" / "demo"
    return Path.cwd() / "fixtures" / "demo"


def cmd_demo(s: Settings, a) -> int:
    from nodetrust.demo import seed_demo

    fixtures = Path(a.fixtures) if a.fixtures else _default_demo_fixtures()
    if not (fixtures / "packuments").is_dir():
        print(f"Demo fixtures not found at {fixtures}. Pass --fixtures <nodetrust-core>/fixtures/demo.",
              file=sys.stderr)
        return 2
    _print(seed_demo(_db(s), fixtures))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nodetrust", description="NodeTrust core (MVP)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("serve", help="run the API + dashboard")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8080)
    sp.add_argument("--i-know-this-is-exposed", action="store_true")
    sp.set_defaults(fn=cmd_serve)
    sp = sub.add_parser("worker", help="feed + fetch (if network allowed) and alert dispatch loop")
    sp.add_argument("--once", action="store_true")
    sp.add_argument("--interval", type=float, default=30.0)
    sp.set_defaults(fn=cmd_worker)
    sp = sub.add_parser("ingest", help="load packument JSON files from a directory (offline)")
    sp.add_argument("path")
    sp.add_argument("--signals", action="store_true", help="also raise crawler signals for ingested versions")
    sp.set_defaults(fn=cmd_ingest)
    sp = sub.add_parser("osv-import", help="import OSV records from a directory or all.zip (offline)")
    sp.add_argument("path")
    sp.set_defaults(fn=cmd_osv)
    sub.add_parser("centrality", help="recompute and cache centrality").set_defaults(fn=cmd_centrality)
    sub.add_parser("dispatch", help="deliver pending alerts once").set_defaults(fn=cmd_dispatch)
    sp = sub.add_parser("create-project", help="create a project and print its admin key")
    sp.add_argument("--name", required=True)
    sp.add_argument("--email")
    sp.set_defaults(fn=cmd_project)
    sp = sub.add_parser("backup", help="consistent online backup + sha256")
    sp.add_argument("out")
    sp.set_defaults(fn=cmd_backup)
    sp = sub.add_parser("restore", help="verify and restore a backup (stop services first)")
    sp.add_argument("backup")
    sp.add_argument("--yes", action="store_true")
    sp.add_argument("--verify-only", action="store_true")
    sp.set_defaults(fn=cmd_restore)
    sp = sub.add_parser("purge", help="apply retention to operational data")
    sp.add_argument("--days", type=int)
    sp.set_defaults(fn=cmd_purge)
    sp = sub.add_parser("demo", help="seed an offline, clearly-labelled demo dataset")
    sp.add_argument("--fixtures", help="demo fixture directory (default: the repo's or ./fixtures/demo)")
    sp.set_defaults(fn=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    from pydantic import ValidationError

    args = build_parser().parse_args(argv)
    try:
        s = Settings()
    except ValidationError as e:
        print(f"Invalid configuration: {e}", file=sys.stderr)
        return 2
    configure_logging(s.log_level)
    return args.fn(s, args)


if __name__ == "__main__":
    raise SystemExit(main())
