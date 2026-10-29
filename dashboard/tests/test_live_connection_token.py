import pytest
from helpers import wait_for_type
from simple_websocket import ConnectionClosed


def test_live_token_missing_closes_connection(live_connect):
    with pytest.raises(ConnectionClosed):
        ws = live_connect(token=None)
        ws.receive(timeout=3)


def test_live_token_empty_closes_connection(live_connect):
    with pytest.raises(ConnectionClosed):
        ws = live_connect(token="")
        ws.receive(timeout=3)


def test_live_token_invalid_closes_connection(live_connect):
    # Replaces the old "placeholder-token" behaviour: only a real login token is accepted.
    with pytest.raises(ConnectionClosed):
        ws = live_connect(token="placeholder-token")
        ws.receive(timeout=3)


def test_live_token_valid_keeps_connection_open(running_client, live_connect):
    ws = live_connect()
    message, _ = wait_for_type(ws, "snapshot", 5)
    assert message is not None
    assert message["payload"]["status"] == "running"
    assert message["payload"]["stats"] is not None
