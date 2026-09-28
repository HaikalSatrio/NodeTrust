"""Authentication and project isolation (NT-017).

Credentials (all sent as `Authorization: Bearer <token>`):
- operator token (NODETRUST_ADMIN_TOKEN): instance-level actions only: create
  projects, curate incidents, import intel. It cannot act inside a project
  (no approvals, overrides or triage on a project's behalf).
- project API key `ntk_<id>_<secret>`: bound to one project and one role:
    ci:    submit scans, read its own scans/verdicts/alerts;
    admin: everything in its project: policy, keys, approvals, overrides, triage.
  Only sha256(secret) is stored; the full key is shown once at creation.

Isolation rule: a project key used on another project's path gets 404 (the
other project's existence is not revealed). This check is centralised in
`require_project`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass

from fastapi import HTTPException, Request

from nodetrust.storage import new_id, utcnow

ROLES = ("ci", "admin")


@dataclass(frozen=True)
class Principal:
    kind: str  # operator | project
    project_id: str | None = None
    role: str | None = None
    key_id: str | None = None

    @property
    def actor(self) -> str:
        return "operator" if self.kind == "operator" else f"key:{self.key_id}({self.role})"


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def create_key(con: sqlite3.Connection, *, project_id: str, role: str, label: str, created_by: str) -> tuple[str, dict]:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    kid = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    con.execute("INSERT INTO api_key(id, project_id, key_hash, role, label, created_at, created_by) "
                "VALUES (?,?,?,?,?,?,?)", (kid, project_id, _hash(secret), role, label[:100], utcnow(), created_by))
    return f"ntk_{kid}_{secret}", {"id": kid, "project_id": project_id, "role": role, "label": label[:100]}


def create_project(con: sqlite3.Connection, *, name: str, alert_email: str | None, created_by: str) -> tuple[dict, str]:
    pid = new_id("prj")
    con.execute("INSERT INTO project(id, name, created_at, alert_email) VALUES (?,?,?,?)",
                (pid, name[:200], utcnow(), alert_email))
    key, _ = create_key(con, project_id=pid, role="admin", label="initial admin key", created_by=created_by)
    return dict(con.execute("SELECT * FROM project WHERE id=?", (pid,)).fetchone()), key


def authenticate(con: sqlite3.Connection, token: str, admin_token: str | None) -> Principal | None:
    if admin_token and hmac.compare_digest(token.encode(), admin_token.encode()):
        return Principal("operator")
    if not token.startswith("ntk_"):
        return None
    parts = token.split("_", 2)
    if len(parts) != 3 or not parts[1] or not parts[2]:
        return None
    row = con.execute("SELECT project_id, key_hash, role, revoked_at FROM api_key WHERE id=?", (parts[1],)).fetchone()
    if row is None or row["revoked_at"] is not None:
        # compare anyway so timing does not reveal whether the key id exists
        hmac.compare_digest(_hash(parts[2]), "0" * 64)
        return None
    if not hmac.compare_digest(_hash(parts[2]), row["key_hash"]):
        return None
    return Principal("project", row["project_id"], row["role"], parts[1])


class AuthThrottle:
    """Per-client-IP limit on failed authentications (sliding window, in memory).

    Keys are 256-bit random, so this is not what stops guessing; it bounds log/DB
    noise and slows credential stuffing. Once an IP exceeds the limit it gets 429
    before any credential check until old failures leave the window. Successful
    requests are never counted. Behind a proxy, configure forwarded_allow_ips so
    the real client IP is used (otherwise all clients share the proxy's budget).
    """

    def __init__(self, max_failures: int, window_s: int, clock=time.monotonic):
        self.max, self.window, self.clock = max_failures, window_s, clock
        self._fail: dict[str, deque] = {}
        self._lock = threading.Lock()

    def _prune(self, q: deque, now: float) -> None:
        while q and now - q[0] > self.window:
            q.popleft()

    def retry_after(self, ip: str) -> int | None:
        with self._lock:
            q = self._fail.get(ip)
            if not q:
                return None
            now = self.clock()
            self._prune(q, now)
            if len(q) < self.max:
                return None
            return max(1, int(self.window - (now - q[0])) + 1)

    def record_failure(self, ip: str) -> None:
        with self._lock:
            q = self._fail.setdefault(ip, deque())
            self._prune(q, self.clock())
            q.append(self.clock())
            if len(self._fail) > 10_000:  # bound memory: drop the stalest entries
                for k in sorted(self._fail, key=lambda k: self._fail[k][-1] if self._fail[k] else 0)[:5_000]:
                    self._fail.pop(k, None)


def bearer(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    if h[:7].lower() == "bearer " and h[7:].strip():
        return h[7:].strip()
    return None


def require_principal(request: Request) -> Principal:
    app = request.app
    ip = request.client.host if request.client else "unknown"
    throttle: AuthThrottle | None = getattr(app.state, "auth_throttle", None)
    if throttle is not None:
        wait = throttle.retry_after(ip)
        if wait is not None:
            raise HTTPException(429, "too many failed authentication attempts", headers={"Retry-After": str(wait)})
    token = bearer(request)
    p = None
    if token:
        with app.state.db.read() as con:
            p = authenticate(con, token, app.state.admin_token)
    if p is None:
        if throttle is not None:
            throttle.record_failure(ip)
        with app.state.db.transaction() as con:
            app.state.db.bump(con, "auth_failures")
        msg = "invalid or revoked credentials" if token else "missing bearer token"
        raise HTTPException(401, msg, headers={"WWW-Authenticate": "Bearer"})
    return p


def require_operator(p: Principal) -> Principal:
    if p.kind != "operator":
        raise HTTPException(403, "operator token required")
    return p


def require_project(p: Principal, project_id: str, roles: tuple[str, ...] = ROLES) -> Principal:
    if p.kind != "project" or p.project_id != project_id:
        raise HTTPException(404, "project not found")
    if p.role not in roles:
        raise HTTPException(403, f"requires role: {' or '.join(roles)}")
    return p
