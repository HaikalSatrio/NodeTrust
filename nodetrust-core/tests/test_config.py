"""NT-002/NT-017: configuration must not accept a guessable operator token."""

import pytest
from pydantic import ValidationError

from nodetrust.cli import main
from nodetrust.config import Settings


@pytest.mark.parametrize("token", ["change-me", "change-me-change-me-change-me-change-me", "short-token", "x" * 31])
def test_placeholder_or_short_admin_token_is_refused(token):
    with pytest.raises(ValidationError) as e:
        Settings(admin_token=token)
    assert token not in str(e.value)  # the rejected value is never echoed


@pytest.mark.parametrize("token", ["", "   "])
def test_empty_admin_token_disables_operator_endpoints(token):
    assert Settings(admin_token=token).admin_token is None


def test_strong_admin_token_is_accepted():
    token = "nodetrust-test-operator-token-0123456789"  # obviously fake, 40 chars
    assert Settings(admin_token=token).admin_token.get_secret_value() == token


def test_cli_reports_bad_config_instead_of_crashing(monkeypatch, capsys):
    monkeypatch.setenv("NODETRUST_ADMIN_TOKEN", "change-me")
    assert main(["centrality"]) == 2
    err = capsys.readouterr().err
    assert "NODETRUST_ADMIN_TOKEN" in err and "change-me" not in err.replace("NODETRUST_ADMIN_TOKEN", "")
