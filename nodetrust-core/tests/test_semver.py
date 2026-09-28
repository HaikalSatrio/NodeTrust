import pytest

from nodetrust.semver import is_exact, max_satisfying, parse_spec, parse_version, satisfies, sort_versions


def test_ordering_follows_semver_precedence():
    ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
               "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
    assert sort_versions(reversed(ordered)) == ordered
    assert parse_version("1.0.0+build.1") == parse_version("1.0.0")


@pytest.mark.parametrize("v,spec,ok", [
    ("1.2.3", "^1.2.3", True), ("1.9.9", "^1.2.3", True), ("2.0.0", "^1.2.3", False),
    ("0.2.9", "^0.2.3", True), ("0.3.0", "^0.2.3", False), ("0.0.3", "^0.0.3", True), ("0.0.4", "^0.0.3", False),
    ("0.0.9", "^0.0", True), ("0.1.0", "^0.0.x", False), ("1.5.0", "^1.x", True),
    ("1.2.9", "~1.2.3", True), ("1.3.0", "~1.2.3", False), ("1.9.0", "~1", True), ("2.0.0", "~1", False),
    ("1.2.3", "1.2.3", True), ("1.2.4", "=1.2.3", False), ("1.2.7", "1.2.x", True), ("1.3.0", "1.2", False),
    ("3.0.0", "*", True), ("0.0.0", "", True),
    ("2.3.4", "1.2.3 - 2.3.4", True), ("2.3.5", "1.2.3 - 2.3.4", False), ("2.3.9", "1.2.3 - 2.3", True),
    ("2.4.0", "1.2.3 - 2.3", False),
    ("1.3.0", ">1.2", True), ("1.2.9", ">1.2", False), ("1.2.9", "<=1.2", True), ("1.3.0", "<=1.2", False),
    ("1.1.9", "<1.2", True), ("1.2.0", "<1.2", False),
    ("1.5.0", ">= 1.2.3 < 2", True), ("2.1.0", "1.x || >=2.5.0", False), ("2.6.0", "1.x || >=2.5.0", True),
    # prerelease rules
    ("1.2.3-beta.2", "^1.2.3-beta.1", True), ("1.5.0-beta", "^1.2.3", False), ("2.0.0-alpha", "^1.2.3", False),
    ("1.2.3-beta", "<1.2.3", False),
    ("4.17.21", "npm:lodash@^4.17.0", True),
])
def test_satisfies_matches_node_semver(v, spec, ok):
    assert satisfies(v, spec) is ok


def test_unresolvable_specs_are_not_guessed():
    for spec in ["latest", "next", "git+https://x/y.git", "file:../a", "user/repo", "workspace:*", "https://x/t.tgz"]:
        assert not parse_spec(spec).resolvable
        assert not satisfies("1.0.0", spec)
    assert parse_spec("npm:lodash@^4").target_name == "lodash"


def test_max_satisfying_and_exact():
    versions = ["1.0.0", "1.2.0", "1.10.0", "2.0.0", "2.1.0-rc.1", "garbage"]
    assert max_satisfying(versions, "^1.0.0") == "1.10.0"
    assert max_satisfying(versions, ">=3") is None
    assert is_exact("1.2.3-rc.1") and not is_exact("^1.2.3") and not is_exact("1.2")
