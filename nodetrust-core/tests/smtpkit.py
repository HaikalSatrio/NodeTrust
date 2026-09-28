"""A tiny SMTP server on 127.0.0.1 for delivery tests: EHLO, STARTTLS, AUTH PLAIN, MAIL/RCPT/DATA.

Certificates are generated per test run (a throwaway CA + a leaf for 127.0.0.1/localhost) and
live only in the pytest tmp directory.
"""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass, field
from pathlib import Path


def make_certs(directory: Path) -> tuple[Path, Path, Path]:
    """Return (ca_pem, leaf_cert_pem, leaf_key_pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)

    def cert(subject, issuer, pub, signer, *, ca, san=None):
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
        if ca:
            b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                              content_commitment=False, key_encipherment=False,
                                              data_encipherment=False, key_agreement=False,
                                              encipher_only=False, decipher_only=False), critical=True)
        return b.sign(signer, hashes.SHA256())

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nodetrust-test-ca")])
    ca = cert(ca_name, ca_name, ca_key.public_key(), ca_key, ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = cert(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]), ca_name, leaf_key.public_key(),
                ca_key, ca=False,
                san=[x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])

    pem = serialization.Encoding.PEM
    paths = directory / "ca.pem", directory / "leaf.pem", directory / "leaf.key"
    paths[0].write_bytes(ca.public_bytes(pem))
    paths[1].write_bytes(leaf.public_bytes(pem))
    paths[2].write_bytes(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    return paths


@dataclass
class Received:
    auth: list[tuple[str, str]] = field(default_factory=list)
    auth_over_tls: list[bool] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)


class SmtpTestServer:
    def __init__(self, tls: ssl.SSLContext | None):
        self.tls = tls
        self.got = Received()
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._sock.close()
        self._thread.join(timeout=5)

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                self._session(conn)
            except (OSError, ssl.SSLError):
                pass  # client aborted (e.g. it rejected our certificate)
            finally:
                conn.close()

    def _session(self, conn):
        secure = False
        rfile = conn.makefile("rb")

        def say(line):
            conn.sendall(line.encode() + b"\r\n")

        say("220 localhost ESMTP nodetrust-test")
        mail = None
        while True:
            raw = rfile.readline()
            if not raw:
                return
            line = raw.decode().rstrip("\r\n")
            verb = line.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                caps = ["localhost"]
                if self.tls and not secure:
                    caps.append("STARTTLS")
                caps.append("AUTH PLAIN")
                for c in caps[:-1]:
                    say("250-" + c)
                say("250 " + caps[-1])
            elif verb == "STARTTLS" and self.tls and not secure:
                say("220 ready for TLS")
                conn = self.tls.wrap_socket(conn, server_side=True)
                rfile = conn.makefile("rb")
                secure = True
            elif verb == "AUTH" and line.upper().startswith("AUTH PLAIN "):
                _, user, pw = base64.b64decode(line.split(" ", 2)[2]).decode().split("\0")
                self.got.auth.append((user, pw))
                self.got.auth_over_tls.append(secure)
                say("235 authenticated")
            elif verb == "MAIL":
                mail = {"from": line, "rcpt": [], "tls": secure}
                say("250 ok")
            elif verb == "RCPT":
                mail["rcpt"].append(line)
                say("250 ok")
            elif verb == "DATA":
                say("354 end with <CRLF>.<CRLF>")
                data = []
                while (chunk := rfile.readline()) not in (b".\r\n", b""):
                    data.append(chunk)
                mail["data"] = b"".join(data).decode()
                self.got.messages.append(mail)
                say("250 queued")
            elif verb == "QUIT":
                say("221 bye")
                return
            elif verb in ("RSET", "NOOP"):
                say("250 ok")
            else:
                say("502 not implemented")
