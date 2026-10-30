import pytest

from backend import session_history


@pytest.fixture
def history_dir(tmp_path, monkeypatch):
    history_file = tmp_path / "sessions.json"
    monkeypatch.setattr(session_history, "_HISTORY_DIR", tmp_path)
    monkeypatch.setattr(session_history, "_HISTORY_FILE", history_file)
    return tmp_path


@pytest.fixture
def sample_records():
    return [
        {
            "source_ip": "192.168.1.10",
            "source_port": 51515,
            "dest_ip": "192.168.1.20",
            "dest_port": 80,
            "protocol": "tcp",
            "timestamp": "2026-10-30T10:00:00Z",
        }
    ]


def test_record_and_list_sessions(history_dir, sample_records):
    stored = session_history.record_sessions(sample_records, "capture123")

    assert len(stored) == 1
    assert stored[0]["capture_id"] == "capture123"
    assert stored[0]["source_ip"] == "192.168.1.10"
    assert stored[0]["destination_ip"] == "192.168.1.20"
    assert stored[0]["tags"] == []
    assert session_history.list_sessions()[0]["session_id"] == stored[0]["session_id"]


def test_get_session(history_dir, sample_records):
    stored = session_history.record_sessions(sample_records)
    session_id = stored[0]["session_id"]

    assert session_history.get_session(session_id) == stored[0]
    assert session_history.get_session("a" * 32) is None


def test_add_and_get_session_tags(history_dir, sample_records):
    stored = session_history.record_sessions(sample_records)
    session_id = stored[0]["session_id"]

    session_history.add_session_tag(session_id, "suspicious")
    session_history.add_session_tag(session_id, "suspicious")

    assert session_history.get_session_tags(session_id) == ["suspicious"]
    assert session_history.list_sessions(tag="suspicious")[0]["session_id"] == session_id


def test_invalid_inputs(history_dir):
    with pytest.raises(ValueError):
        session_history.record_sessions("not a list")

    with pytest.raises(ValueError):
        session_history.list_sessions(limit=0)

    with pytest.raises(ValueError):
        session_history.add_session_tag("invalid-id", "test")

    with pytest.raises(ValueError):
        session_history.add_session_tag("a" * 32, "")


def test_invalid_records_are_skipped(history_dir):
    stored = session_history.record_sessions(
        [None, {}, {"source_ip": "192.168.1.10"}]
    )

    assert stored == []
    assert session_history.list_sessions() == []


def test_sessions_persist_between_reads(history_dir, sample_records):
    stored = session_history.record_sessions(sample_records)
    session_id = stored[0]["session_id"]

    loaded = session_history.get_session(session_id)

    assert loaded is not None
    assert loaded["protocol"] == "tcp"
