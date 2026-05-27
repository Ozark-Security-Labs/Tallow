import os
import socket
import urllib.request

import pytest


@pytest.fixture(autouse=True)
def _network_off_guard(monkeypatch: pytest.MonkeyPatch):
    if os.environ.get("TALLOW_ANALYZER_NETWORK_OFF") != "1":
        yield
        return

    def guarded(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError("network disabled in analyzer tests")

    monkeypatch.setattr(socket, "socket", guarded)
    monkeypatch.setattr(socket, "create_connection", guarded)
    monkeypatch.setattr(socket, "create_server", guarded)
    monkeypatch.setattr(urllib.request, "urlopen", guarded)
    yield
