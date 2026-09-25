"""NT-023 SMTP delivery against a real SMTP conversation on 127.0.0.1 (no external mail server)."""

import smtplib
import ssl

import pytest

pytest.importorskip("cryptography")

from nodetrust.alerts import SmtpSender  # noqa: E402
from smtpkit import SmtpTestServer, make_certs  # noqa: E402

HEADERS = {"X-NodeTrust-Alert": "alr_test", "X-NodeTrust-Dedup": "0123456789abcdef"}


@pytest.fixture
def certs(tmp_path):
    return make_certs(tmp_path)


def server_tls(certs) -> ssl.SSLContext:
    _, leaf, key = certs
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(leaf, key)
    return ctx


def sender(port, **kw) -> SmtpSender:
    return SmtpSender("127.0.0.1", port, "nt-user", "s3cret-pw", "nodetrust@example.test", allow_network=True,
                      timeout=5, **kw)


def test_delivers_over_verified_starttls(certs):
    ca = certs[0]
    with SmtpTestServer(tls=server_tls(certs)) as srv:
        sender(srv.port, ssl_context=ssl.create_default_context(cafile=ca)).send(
            "owner@example.test", "[NodeTrust][CRITICAL] pkg in app", "body line", HEADERS)
    assert srv.got.auth == [("nt-user", "s3cret-pw")] and srv.got.auth_over_tls == [True]
    [msg] = srv.got.messages
    assert msg["tls"] and "owner@example.test" in msg["rcpt"][0]
    assert "Subject: [NodeTrust][CRITICAL] pkg in app" in msg["data"]
    assert "X-NodeTrust-Alert: alr_test" in msg["data"]


def test_untrusted_certificate_is_refused_before_credentials(certs):
    # Default context = system CAs, which do not include the throwaway test CA. With smtplib's
    # own default (no verification) this used to log in and send the password to the server.
    with SmtpTestServer(tls=server_tls(certs)) as srv:
        with pytest.raises(ssl.SSLCertVerificationError):
            sender(srv.port).send("owner@example.test", "s", "b", HEADERS)
    assert srv.got.auth == [] and srv.got.messages == []


def test_server_without_starttls_gets_nothing():
    with SmtpTestServer(tls=None) as srv:
        with pytest.raises(smtplib.SMTPNotSupportedError):
            sender(srv.port).send("owner@example.test", "s", "b", HEADERS)
    assert srv.got.auth == [] and srv.got.messages == []


def test_smtp_needs_network_flag():
    with pytest.raises(RuntimeError, match="ALLOW_NETWORK"):
        SmtpSender("127.0.0.1", 25, None, None, "x@example.test", allow_network=False)
