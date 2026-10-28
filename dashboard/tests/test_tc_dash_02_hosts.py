from helpers import load_ground_truth, wait_for_type


def test_tc_dash_02_hosts_arrive_within_5s(client, live_connect):
    ws = live_connect()
    client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    message, waited = wait_for_type(ws, "hosts", 5)
    assert message is not None
    assert waited <= 5


def test_tc_dash_02_hosts_match_mock_data(running_client, live_connect):
    expected = load_ground_truth()["hosts"]
    ws = live_connect()
    message, _ = wait_for_type(ws, "hosts", 5)
    hosts = message["data"]["hosts"]
    assert [h["ip"] for h in hosts] == [h["ip"] for h in expected]
    assert [h["mac"] for h in hosts] == [h["mac"] for h in expected]


def test_tc_dash_02_packets_arrive_newest_first_and_capped(client, live_connect):
    ws = live_connect()
    client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    message, waited = wait_for_type(ws, "packets", 5)
    packets = message["data"]["packets"]
    times = [p["time"] for p in packets]
    assert waited <= 5
    assert len(packets) <= 20
    assert times == sorted(times, reverse=True)