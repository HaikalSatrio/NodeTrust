import json
import socket

import pytest

from nodetrust.storage import Database


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Hard guarantee that unit tests never open a non-loopback connection."""
    real_connect = socket.socket.connect

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise RuntimeError(f"test attempted outbound connection to {address!r}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "nt.db")


def packument(name, versions, *, maintainers=("alice",), modified="2026-09-01T00:00:00.000Z"):
    """versions: {ver: {deps: {}, publisher: str, maintainers: [..], scripts: {}, time: iso, integrity: str,
    optional: {}, peer: {}, repository: str}}"""
    doc = {"_id": name, "name": name, "dist-tags": {}, "maintainers": [{"name": m, "email": f"{m}@x"} for m in maintainers],
           "time": {"modified": modified}, "versions": {}}
    for ver, spec in versions.items():
        vd = {"name": name, "version": ver,
              "dependencies": dict(spec.get("deps", {})),
              "maintainers": [{"name": m, "email": f"{m}@x"} for m in spec.get("maintainers", maintainers)],
              "_npmUser": {"name": spec.get("publisher", maintainers[0]), "email": "x@x"},
              "dist": {"integrity": spec.get("integrity", f"sha512-{name}-{ver}"), "shasum": "0" * 40}}
        if spec.get("optional"):
            vd["optionalDependencies"] = dict(spec["optional"])
            vd["dependencies"].update(spec["optional"])
        if spec.get("peer"):
            vd["peerDependencies"] = dict(spec["peer"])
        if spec.get("scripts"):
            vd["scripts"] = dict(spec["scripts"])
        if spec.get("repository"):
            vd["repository"] = {"type": "git", "url": spec["repository"]}
        doc["versions"][ver] = vd
        doc["time"][ver] = spec.get("time", "2026-01-01T00:00:00.000Z")
        doc["dist-tags"]["latest"] = ver
    return doc


def as_body(doc) -> bytes:
    return json.dumps(doc).encode()
