import time

import pytest

from backend import log_rotation


def test_rotates_log_when_size_threshold_is_reached(tmp_path):
    log_file = tmp_path / "application.log"
    log_file.write_text("x" * 100, encoding="utf-8")

    result = log_rotation.rotate_logs(
        tmp_path,
        max_bytes=100,
        max_age_seconds=3600,
        now=time.time(),
    )

    assert len(result["rotated"]) == 1
    assert not result["failed"]
    assert not log_file.exists()


def test_rotates_log_when_time_threshold_is_reached(tmp_path):
    log_file = tmp_path / "application.log"
    log_file.write_text("small log", encoding="utf-8")
    old_time = time.time() - 7200
    log_file.touch()
    import os
    os.utime(log_file, (old_time, old_time))

    result = log_rotation.rotate_logs(
        tmp_path,
        max_bytes=10000,
        max_age_seconds=3600,
        now=time.time(),
    )

    assert len(result["rotated"]) == 1
    assert not result["failed"]


def test_does_not_rotate_small_recent_log(tmp_path):
    log_file = tmp_path / "application.log"
    log_file.write_text("recent", encoding="utf-8")

    result = log_rotation.rotate_logs(
        tmp_path,
        max_bytes=10000,
        max_age_seconds=3600,
        now=time.time(),
    )

    assert result["rotated"] == []
    assert result["failed"] == []
    assert log_file.exists()


def test_rejects_invalid_rotation_configuration(tmp_path):
    with pytest.raises(ValueError):
        log_rotation.rotate_logs(tmp_path, max_bytes=0)


def test_requires_existing_log_directory(tmp_path):
    with pytest.raises(FileNotFoundError):
        log_rotation.rotate_logs(tmp_path / "missing")


def test_enforces_backup_count(tmp_path):
    log_file = tmp_path / "application.log"
    log_file.write_text("x" * 100, encoding="utf-8")

    for index in range(3):
        backup = tmp_path / f"application.log.old{index}.rotated"
        backup.write_text("old", encoding="utf-8")
        os_time = time.time() - (100 + index)
        import os
        os.utime(backup, (os_time, os_time))

    result = log_rotation.rotate_logs(
        tmp_path,
        max_bytes=100,
        max_age_seconds=3600,
        backup_count=2,
    )

    assert not result["failed"]
    backups = list(tmp_path.glob("application.log.*.rotated"))
    assert len(backups) == 2
