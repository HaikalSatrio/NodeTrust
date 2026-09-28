"""HTTP access for crawler and intel adapters.

All outbound traffic goes through `Transport`. The real implementation refuses to
run unless NODETRUST_ALLOW_NETWORK=true, so tests, CI and offline demos cannot
reach the internet by accident. Tests use `FakeTransport`.

`fetch_with_retry` gives the bounded behaviour NT-007 asks for: timeouts,
exponential backoff with jitter, Retry-After on 429/503, a byte cap, and a
token-bucket rate limit shared by the caller.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol


class NetworkDisabled(RuntimeError):
    pass


class TransportError(RuntimeError):
    """Retryable I/O failure (connection reset, timeout, 5xx after retries)."""


class ResponseTooLarge(RuntimeError):
    pass


@dataclass
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


class Transport(Protocol):
    def request(self, method: str, url: str, *, headers: Mapping[str, str] | None = None,
                body: bytes | None = None, timeout: float, max_bytes: int) -> Response: ...


class DisabledTransport:
    def request(self, method, url, *, headers=None, body=None, timeout, max_bytes):  # noqa: D401
        raise NetworkDisabled("network access is disabled (set NODETRUST_ALLOW_NETWORK=true to enable)")


class HttpxTransport:
    """Real transport. Only constructed when network is explicitly allowed."""

    def __init__(self, user_agent: str = "nodetrust/0.1"):
        import httpx  # local import: keeps offline code paths free of network libs

        self._client = httpx.Client(headers={"user-agent": user_agent}, follow_redirects=False)

    def request(self, method, url, *, headers=None, body=None, timeout, max_bytes):
        import httpx

        try:
            with self._client.stream(method, url, headers=dict(headers or {}), content=body,
                                     timeout=timeout) as r:
                declared = r.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise ResponseTooLarge(f"{url}: content-length {declared} > {max_bytes}")
                chunks, total = [], 0
                for chunk in r.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise ResponseTooLarge(f"{url}: body exceeds {max_bytes} bytes")
                    chunks.append(chunk)
                return Response(r.status_code, b"".join(chunks), dict(r.headers))
        except httpx.TimeoutException as e:
            raise TransportError(f"timeout: {url}") from e
        except httpx.TransportError as e:
            raise TransportError(f"transport error: {url}: {type(e).__name__}") from e


def make_transport(allow_network: bool) -> Transport:
    return HttpxTransport() if allow_network else DisabledTransport()


class FakeTransport:
    """Scriptable transport for tests: map URL -> list of responses/exceptions.
    The last scripted item repeats. Records every call."""

    def __init__(self, routes: dict[str, list] | None = None):
        self.routes: dict[str, list] = {k: list(v) for k, v in (routes or {}).items()}
        self.calls: list[tuple[str, str]] = []

    def add(self, url: str, *items) -> None:
        self.routes.setdefault(url, []).extend(items)

    def request(self, method, url, *, headers=None, body=None, timeout, max_bytes):
        self.calls.append((method, url))
        items = self.routes.get(url)
        if not items:
            return Response(404, b'{"error":"not found"}')
        item = items.pop(0) if len(items) > 1 else items[0]
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, Response):
            if len(item.body) > max_bytes:
                raise ResponseTooLarge(url)
            return item
        raise TypeError(item)


class RateLimiter:
    """Token bucket; `acquire` blocks via the injected sleep function."""

    def __init__(self, rate_per_s: float, burst: int = 1, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.rate = max(rate_per_s, 0.001)
        self.capacity = max(burst, 1)
        self.tokens = float(self.capacity)
        self.clock, self.sleep = clock, sleep
        self.last = clock()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = self.clock()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                self.sleep(wait)
                self.last = self.clock()
                self.tokens = 0
            else:
                self.tokens -= 1


RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


def fetch_with_retry(transport: Transport, method: str, url: str, *, timeout: float, max_bytes: int,
                     max_attempts: int = 4, base_delay: float = 0.5, max_delay: float = 30.0,
                     limiter: RateLimiter | None = None, headers: Mapping[str, str] | None = None,
                     body: bytes | None = None, sleep: Callable[[float], None] = time.sleep,
                     rng: random.Random | None = None) -> Response:
    """Return the first non-retryable response. Raise TransportError when retries
    are exhausted. 4xx other than 408/425/429 are returned to the caller as-is."""
    rng = rng or random.Random()
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        if limiter:
            limiter.acquire()
        try:
            resp = transport.request(method, url, headers=headers, body=body, timeout=timeout, max_bytes=max_bytes)
        except (NetworkDisabled, ResponseTooLarge):
            raise
        except TransportError as e:
            last_exc = e
            resp = None
        if resp is not None and resp.status not in RETRYABLE_STATUS:
            return resp
        if attempt == max_attempts:
            break
        delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
        delay = delay / 2 + rng.random() * delay / 2  # jitter
        if resp is not None:
            ra = resp.header("retry-after")
            if ra and ra.strip().isdigit():
                delay = min(max_delay, max(delay, float(ra)))
            last_exc = TransportError(f"HTTP {resp.status} from {url}")
        sleep(delay)
    raise TransportError(f"giving up after {max_attempts} attempts: {last_exc}")
