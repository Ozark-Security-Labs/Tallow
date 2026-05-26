import socket

import pytest


@pytest.fixture
def network_off(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TALLOW_ANALYZER_NETWORK_OFF", "1")


    def guarded(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError("network disabled in analyzer tests")

    monkeypatch.setattr(socket, "socket", guarded)
    yield


def test_network_off_blocks_socket(network_off):
    with pytest.raises(OSError, match="network disabled"):
        socket.socket()
