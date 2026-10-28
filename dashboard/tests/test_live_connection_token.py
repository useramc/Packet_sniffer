import pytest
from simple_websocket import ConnectionClosed

from helpers import wait_for_type


def test_live_token_missing_closes_connection(live_connect):
    with pytest.raises(ConnectionClosed):
        ws = live_connect(token=None)
        ws.receive(timeout=3)


def test_live_token_empty_closes_connection(live_connect):
    with pytest.raises(ConnectionClosed):
        ws = live_connect(token="")
        ws.receive(timeout=3)


def test_live_token_present_keeps_connection_open(running_client, live_connect):
    ws = live_connect(token="placeholder-token")
    message, _ = wait_for_type(ws, "stats", 5)
    assert message is not None