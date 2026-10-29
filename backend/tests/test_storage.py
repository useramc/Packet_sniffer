import json
import time

import pytest
from backend import storage


@pytest.fixture
def storage_dir(tmp_path, monkeypatch):
    directory = tmp_path / "stored_captures"
    monkeypatch.setattr(storage, "STORAGE_DIR", directory)
    monkeypatch.setattr(storage, "RETENTION_DAYS", 30)
    return directory


@pytest.fixture
def capture_inputs(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"test-pcap-data")

    logs_dir = tmp_path / "zeek_logs"
    logs_dir.mkdir()
    (logs_dir / "conn.log").write_text(
        "#separator \\x09\n"
        "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto\n"
        "1234567890.0 C1 192.168.1.10 12345 192.168.1.20 80 tcp\n",
        encoding="utf-8",
    )

    analysis_result = {
        "status": "success",
        "output_dir": str(logs_dir),
        "elapsed_seconds": 0.5,
    }

    return pcap, analysis_result


def test_store_and_retrieve_capture(
    storage_dir, capture_inputs
):
    pcap, analysis_result = capture_inputs

    result = storage.store_capture(pcap, analysis_result)

    capture_id = result["capture_id"]
    metadata = storage.get_capture(capture_id)

    assert metadata["capture_id"] == capture_id
    assert (storage_dir / capture_id / "capture.pcap").is_file()
    assert (
        storage_dir / capture_id / "zeek_logs" / "conn.log"
    ).is_file()


def test_stored_capture_integrity(
    storage_dir, capture_inputs
):
    pcap, analysis_result = capture_inputs

    result = storage.store_capture(pcap, analysis_result)

    verification = storage.verify_capture(result["capture_id"])

    assert verification["verified"] is True
    assert all(
        item["size_matches"] and item["checksum_matches"]
        for item in verification["files"]
    )


def test_detect_modified_stored_file(
    storage_dir, capture_inputs
):
    pcap, analysis_result = capture_inputs

    result = storage.store_capture(pcap, analysis_result)
    capture_id = result["capture_id"]

    metadata = storage.get_capture(capture_id)
    pcap_entry = next(
        item for item in metadata["files"]
        if item["path"].endswith(".pcap")
    )

    stored_file = storage.get_stored_file(
        capture_id, pcap_entry["path"]
    )
    stored_file.write_bytes(b"modified-data")

    verification = storage.verify_capture(capture_id)

    assert verification["verified"] is False


def test_missing_capture_raises_error(storage_dir):
    with pytest.raises(FileNotFoundError):
        storage.get_capture("missing-capture")


def test_invalid_capture_id_is_rejected(storage_dir):
    with pytest.raises(ValueError):
        storage.get_capture("../outside")


def test_file_retrieval_rejects_path_traversal(
    storage_dir, capture_inputs
):
    pcap, analysis_result = capture_inputs
    result = storage.store_capture(pcap, analysis_result)

    with pytest.raises(ValueError):
        storage.get_stored_file(
            result["capture_id"], "../../outside.txt"
        )


def test_retention_removes_expired_capture(
    storage_dir, capture_inputs, monkeypatch
):
    pcap, analysis_result = capture_inputs
    result = storage.store_capture(pcap, analysis_result)

    capture_id = result["capture_id"]
    capture_path = storage_dir / capture_id

    metadata_path = capture_path / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["created_at"] = time.time() - (3 * 86400)
    metadata_path.write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    outcome = storage.apply_retention(retention_days=1)

    assert capture_id in outcome["deleted"]
    assert not capture_path.exists()


def test_list_captures_returns_stored_capture(
    storage_dir, capture_inputs
):
    pcap, analysis_result = capture_inputs
    result = storage.store_capture(pcap, analysis_result)

    captures = storage.list_captures()

    assert any(
        item["capture_id"] == result["capture_id"]
        for item in captures
    )

