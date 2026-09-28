"""Semver ordering and npm range matching.

Range matcher used by the NT-005 registry resolver. Exact client resolution
comes from the existing lockfile/SBOM path, not from a registry range guess.

Semantics follow node-semver (non-loose):
- comparators, x-ranges, tilde, caret, hyphen ranges and '||' unions;
- a prerelease version only satisfies a comparator set in which some comparator
  shares its [major, minor, patch] and itself carries a prerelease.
Specs that are not ranges (dist-tags, git/url/file, workspace) are reported as
unresolvable instead of guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

__all__ = [
    "Version",
    "SemverError",
    "parse_version",
    "is_exact",
    "Spec",
    "parse_spec",
    "satisfies",
    "max_satisfying",
    "sort_versions",
]


class SemverError(ValueError):
    pass


_VERSION_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


def _pre_key(pre: tuple[str, ...]):
    # Versions without prerelease sort after any prerelease of the same triple.
    if not pre:
        return (1,)
    return (0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre))


@total_ordering
@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    def _key(self):
        return (self.major, self.minor, self.patch, _pre_key(self.prerelease))

    def __lt__(self, other: "Version") -> bool:
        return self._key() < other._key()

    def __eq__(self, other: object) -> bool:  # build metadata ignored for precedence
        return isinstance(other, Version) and self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    @property
    def triple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __str__(self) -> str:
        s = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            s += "-" + ".".join(self.prerelease)
        if self.build:
            s += "+" + ".".join(self.build)
        return s


def parse_version(text: str) -> Version:
    m = _VERSION_RE.match(text.strip())
    if not m:
        raise SemverError(f"invalid version: {text!r}")
    pre = tuple(m.group(4).split(".")) if m.group(4) else ()
    build = tuple(m.group(5).split(".")) if m.group(5) else ()
    return Version(int(m.group(1)), int(m.group(2)), int(m.group(3)), pre, build)


def is_exact(text: str) -> bool:
    try:
        parse_version(text)
        return True
    except SemverError:
        return False


def sort_versions(versions, reverse: bool = False) -> list[str]:
    """Sort version strings by semver precedence; invalid ones are dropped."""
    parsed = []
    for v in versions:
        try:
            parsed.append((parse_version(v), v))
        except SemverError:
            continue
    parsed.sort(key=lambda t: t[0], reverse=reverse)
    return [v for _, v in parsed]


# ---------------------------------------------------------------- ranges

_X = {"x", "X", "*"}
_PARTIAL_RE = re.compile(
    r"^v?(?P<maj>0|[1-9]\d*|[xX*])"
    r"(?:\.(?P<min>0|[1-9]\d*|[xX*])"
    r"(?:\.(?P<pat>0|[1-9]\d*|[xX*])"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r")?)?$"
)
_COMPARATOR_RE = re.compile(r"^(?P<op><=|>=|<|>|=|~>|~|\^)?\s*(?P<ver>\S+)$")


@dataclass(frozen=True)
class _Partial:
    major: int | None
    minor: int | None
    patch: int | None
    pre: tuple[str, ...]

    @property
    def is_full(self) -> bool:
        return self.major is not None and self.minor is not None and self.patch is not None


def _parse_partial(text: str) -> _Partial:
    m = _PARTIAL_RE.match(text)
    if not m:
        raise SemverError(f"invalid version in range: {text!r}")

    def num(g):
        v = m.group(g)
        return None if v is None or v in _X else int(v)

    maj, mi, pa = num("maj"), num("min"), num("pat")
    if ((m.group("maj") in _X and any(m.group(g) not in _X | {None} for g in ("min", "pat")))
            or (m.group("min") in _X and m.group("pat") not in _X | {None})):
        raise SemverError("numeric component after wildcard")
    if maj is None:
        mi = pa = None
    elif mi is None:
        pa = None
    pre = tuple(m.group("pre").split(".")) if m.group("pre") and pa is not None else ()
    if any(p.isdigit() and len(p) > 1 and p.startswith("0") for p in pre):
        raise SemverError("numeric prerelease identifiers cannot have leading zeros")
    return _Partial(maj, mi, pa, pre)


def _v(maj, mi, pa, pre=()) -> Version:
    return Version(maj, mi, pa, tuple(pre))


def _zero(maj, mi, pa) -> Version:  # lower-than-any-prerelease upper bound "X.Y.Z-0"
    return Version(maj, mi, pa, ("0",))


Comparator = tuple[str, Version]


def _desugar(op: str | None, p: _Partial) -> list[Comparator]:
    op = op or "="
    if op == "~>":
        op = "~"
    if p.major is None:  # '*' / 'x'
        if op in ("<", ">"):
            return [("<", _zero(0, 0, 0))]  # matches nothing
        return [(">=", _v(0, 0, 0))]
    M, m, pt = p.major, p.minor, p.patch

    if op == "^":
        lo = _v(M, m or 0, pt or 0, p.pre)
        if M != 0 or m is None:
            hi = _zero(M + 1, 0, 0)
        elif m != 0 or pt is None:
            hi = _zero(0, m + 1, 0)
        else:
            hi = _zero(0, 0, pt + 1)
        return [(">=", lo), ("<", hi)]
    if op == "~":
        lo = _v(M, m or 0, pt or 0, p.pre)
        hi = _zero(M + 1, 0, 0) if m is None else _zero(M, m + 1, 0)
        return [(">=", lo), ("<", hi)]
    if p.is_full:
        return [(op if op != "=" else "=", _v(M, m, pt, p.pre))]
    # partial with plain comparator
    if op == "=":
        lo = _v(M, m or 0, 0)
        hi = _zero(M + 1, 0, 0) if m is None else _zero(M, m + 1, 0)
        return [(">=", lo), ("<", hi)]
    if op == ">":
        return [(">=", _v(M + 1, 0, 0) if m is None else _v(M, m + 1, 0))]
    if op == ">=":
        return [(">=", _v(M, m or 0, 0))]
    if op == "<":
        return [("<", _zero(M, m or 0, 0))]
    if op == "<=":
        return [("<", _zero(M + 1, 0, 0) if m is None else _zero(M, m + 1, 0))]
    raise SemverError(f"unsupported operator {op!r}")


def _parse_set(text: str) -> list[Comparator]:
    text = text.strip()
    if text in ("", "*", "x", "X"):
        return [(">=", _v(0, 0, 0))]
    hy = re.match(r"^(\S+)\s+-\s+(\S+)$", text)
    if hy:
        a, b = _parse_partial(hy.group(1)), _parse_partial(hy.group(2))
        lo = [(">=", _v(0, 0, 0))] if a.major is None else [(">=", _v(a.major, a.minor or 0, a.patch or 0, a.pre))]
        if b.major is None:
            hi: list[Comparator] = []
        elif b.is_full:
            hi = [("<=", _v(b.major, b.minor, b.patch, b.pre))]
        elif b.minor is None:
            hi = [("<", _zero(b.major + 1, 0, 0))]
        else:
            hi = [("<", _zero(b.major, b.minor + 1, 0))]
        return lo + hi
    # glue operators separated from versions by whitespace (">= 1.2.3")
    text = re.sub(r"(<=|>=|<|>|=|~>|~|\^)\s+", r"\1", text)
    out: list[Comparator] = []
    for tok in text.split():
        m = _COMPARATOR_RE.match(tok)
        if not m:
            raise SemverError(f"invalid comparator: {tok!r}")
        out.extend(_desugar(m.group("op"), _parse_partial(m.group("ver"))))
    return out


@dataclass(frozen=True)
class Spec:
    """A parsed dependency spec.

    kind: 'range' (sets usable), 'alias' (npm:<name>@<range>), 'tag' (dist-tag),
    'unsupported' (git/url/file/workspace...). Only 'range'/'alias' can resolve.
    """

    raw: str
    kind: str
    target_name: str | None = None
    sets: tuple[tuple[Comparator, ...], ...] = ()

    @property
    def resolvable(self) -> bool:
        return self.kind in ("range", "alias")


_UNSUPPORTED_PREFIXES = ("file:", "git+", "git:", "http:", "https:", "github:", "gitlab:", "bitbucket:",
                         "link:", "workspace:", "portal:", "patch:")


def parse_spec(raw: str) -> Spec:
    s = (raw or "").strip()
    if s.startswith("npm:"):
        from nodetrust.contracts import valid_npm_name

        body = s[4:]
        at = body.rfind("@")
        if at <= 0:
            # An omitted alias spec means a dist-tag lookup, not any version.
            return Spec(raw, "unsupported", body.lower())
        name, rng = body[:at].lower(), body[at + 1:]
        if not valid_npm_name(name) or not rng:
            return Spec(raw, "unsupported", name)
        inner = parse_spec(rng)
        if inner.kind != "range":
            return Spec(raw, "unsupported", name)
        return Spec(raw, "alias", name, inner.sets)
    if s.startswith(_UNSUPPORTED_PREFIXES) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s):
        return Spec(raw, "unsupported")
    try:
        sets = tuple(tuple(_parse_set(part)) for part in s.split("||")) if s else (((">=", _v(0, 0, 0)),),)
    except SemverError:
        if re.match(r"^[A-Za-z][\w.-]*$", s):
            return Spec(raw, "tag")
        return Spec(raw, "unsupported")
    if s == "latest":
        return Spec(raw, "tag")
    return Spec(raw, "range", None, sets)


def _test(op: str, a: Version, b: Version) -> bool:
    if op == "=":
        return a == b
    if op == "<":
        return a < b
    if op == "<=":
        return a <= b
    if op == ">":
        return a > b
    if op == ">=":
        return a >= b
    raise SemverError(op)


def _set_ok(v: Version, comps: tuple[Comparator, ...]) -> bool:
    if not all(_test(op, v, cv) for op, cv in comps):
        return False
    if v.prerelease:
        return any(cv.prerelease and cv.triple == v.triple for _, cv in comps)
    return True


def satisfies(version: str | Version, spec: str | Spec) -> bool:
    try:
        v = version if isinstance(version, Version) else parse_version(version)
    except SemverError:
        return False
    sp = spec if isinstance(spec, Spec) else parse_spec(spec)
    if not sp.resolvable:
        return False
    return any(_set_ok(v, s) for s in sp.sets)


def max_satisfying(versions, spec: str | Spec) -> str | None:
    sp = spec if isinstance(spec, Spec) else parse_spec(spec)
    best: tuple[Version, str] | None = None
    for raw in versions:
        try:
            v = parse_version(raw)
        except SemverError:
            continue
        if satisfies(v, sp) and (best is None or v > best[0]):
            best = (v, raw)
    return best[1] if best else None
