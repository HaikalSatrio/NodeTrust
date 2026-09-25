"""HTTP client for the NodeTrust API (stdlib urllib).

Total time budget (default 60 s, NT-001 D06) covers every attempt and backoff.
Retries only on connection errors, timeouts, 429 and 5xx; resubmitting is safe
because the server de-duplicates scans by (project, commit, SBOM hash).
Auth/validation errors (401/403/404/413/422) are not retried.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from nodetrust_ci import __version__

RETRY_STATUS = {429, 500, 502, 503, 504}


class ApiUnavailable(RuntimeError):
    """Could not get an assessment in time (network, timeout, 5xx)."""


class ApiConfigError(RuntimeError):
    """Credentials, project or payload rejected: a configuration problem."""

    def __init__(self, status: int, message: str, details=None):
        super().__init__(f"HTTP {status}: {message}")
        self.status, self.details = status, details


@dataclass
class HttpResult:
    status: int
    body: bytes


def _urllib_send(url: str, data: bytes, headers: dict, timeout: float) -> HttpResult:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - URL is operator-configured
            return HttpResult(r.status, r.read(20 * 1024 * 1024))
    except urllib.error.HTTPError as e:
        return HttpResult(e.code, e.read(1024 * 1024))


def submit(api_url: str, project_id: str, api_key: str, payload: dict, *, budget_s: float = 60.0,
           send: Callable[[str, bytes, dict, float], HttpResult] = _urllib_send,
           clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> dict:
    if not api_url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise ApiConfigError(0, "api-url must use https:// (plain http is only allowed for localhost)")
    url = f"{api_url.rstrip('/')}/v1/projects/{project_id}/scans"
    data = json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
               "User-Agent": f"nodetrust-ci/{__version__}"}
    start = clock()
    attempt, delay, last = 0, 2.0, "no attempt made"
    while True:
        remaining = budget_s - (clock() - start)
        if remaining <= 0.5:
            raise ApiUnavailable(f"no assessment within {budget_s:.0f}s ({last})")
        attempt += 1
        try:
            res = send(url, data, headers, min(30.0, remaining))
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as e:
            last = f"attempt {attempt}: {type(e).__name__}"
        else:
            if res.status == 200:
                try:
                    return json.loads(res.body)
                except ValueError:
                    last = f"attempt {attempt}: invalid JSON from server"
            elif res.status in RETRY_STATUS:
                last = f"attempt {attempt}: HTTP {res.status}"
            else:
                try:
                    err = json.loads(res.body).get("error", {})
                except (ValueError, AttributeError):
                    err = {}
                raise ApiConfigError(res.status, err.get("message") or "request rejected", err.get("details"))
        wait = min(delay, max(0.0, budget_s - (clock() - start) - 0.5))
        if wait <= 0:
            raise ApiUnavailable(f"no assessment within {budget_s:.0f}s ({last})")
        sleep(wait)
        delay *= 2
