import socket
import urllib.request

import pytest


@pytest.fixture
def network_off(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TALLOW_ANALYZER_NETWORK_OFF", "1")

    def guarded(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError("network disabled in analyzer tests")

    monkeypatch.setattr(socket, "socket", guarded)
    monkeypatch.setattr(socket, "create_connection", guarded)
    monkeypatch.setattr(urllib.request, "urlopen", guarded)
    yield


def test_network_off_blocks_socket(network_off):
    with pytest.raises(OSError, match="network disabled"):
        socket.socket()


def test_network_off_blocks_common_helpers(network_off):
    with pytest.raises(OSError, match="network disabled"):
        socket.create_connection(("example.test", 443))
    with pytest.raises(OSError, match="network disabled"):
        urllib.request.urlopen("https://example.test")  # noqa: S310 synthetic blocked URL
