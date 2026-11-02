"""Size- and time-based rotation for application log files."""

import logging
import os
import time
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent

logger = logging.getLogger(__name__)

DEFAULT_MAX_BYTES = int(
    os.environ.get("PACKET_LOG_MAX_BYTES", str(10 * 1024 * 1024))
)
DEFAULT_MAX_AGE_SECONDS = int(
    os.environ.get("PACKET_LOG_MAX_AGE_SECONDS", str(24 * 60 * 60))
)
DEFAULT_BACKUP_COUNT = int(
    os.environ.get("PACKET_LOG_BACKUP_COUNT", "5")
)


def rotate_logs(
    log_directory,
    max_bytes=None,
    max_age_seconds=None,
    backup_count=None,
    now=None,
):
    """Rotate logs that exceed a size or age threshold.

    Rotated files use timestamped names. Old backups are removed when
    their count exceeds the configured backup limit.
    """
    directory = Path(log_directory).resolve()
    size_limit = DEFAULT_MAX_BYTES if max_bytes is None else max_bytes
    age_limit = (
        DEFAULT_MAX_AGE_SECONDS
        if max_age_seconds is None
        else max_age_seconds
    )
    backups_limit = (
        DEFAULT_BACKUP_COUNT if backup_count is None else backup_count
    )
    current_time = time.time() if now is None else now

    if size_limit <= 0:
        raise ValueError("max_bytes must be positive.")
    if age_limit <= 0:
        raise ValueError("max_age_seconds must be positive.")
    if backups_limit < 0:
        raise ValueError("backup_count cannot be negative.")

    if not directory.is_dir():
        raise FileNotFoundError("Log directory does not exist.")

    rotated = []
    failed = []

    for log_path in sorted(directory.glob("*.log")):
        try:
            stat = log_path.stat()
            oversized = stat.st_size >= size_limit
            expired = current_time - stat.st_mtime >= age_limit

            if not oversized and not expired:
                continue

            timestamp = time.strftime(
                "%Y%m%d-%H%M%S",
                time.localtime(current_time),
            )
            archive = log_path.with_name(
                f"{log_path.name}.{timestamp}.rotated"
            )

            suffix = 1
            while archive.exists():
                archive = log_path.with_name(
                    f"{log_path.name}.{timestamp}.{suffix}.rotated"
                )
                suffix += 1

            log_path.rename(archive)
            rotated.append(str(archive))

            backups = sorted(
                log_path.parent.glob(f"{log_path.name}.*.rotated"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )

            for old_backup in backups[backups_limit:]:
                old_backup.unlink()

        except OSError as exc:
            logger.exception("Log rotation failed for %s", log_path)
            failed.append({"path": str(log_path), "error": str(exc)})

    return {"rotated": rotated, "failed": failed}

class SizeAndTimeRotatingHandler(logging.Handler):
    """Write application logs and rotate them by size or elapsed time."""

    def __init__(
        self,
        log_path,
        max_bytes=None,
        max_age_seconds=None,
        backup_count=None,
    ):
        super().__init__()

        self.log_path = Path(log_path).resolve()
        self.max_bytes = (
            DEFAULT_MAX_BYTES if max_bytes is None else max_bytes
        )
        self.max_age_seconds = (
            DEFAULT_MAX_AGE_SECONDS
            if max_age_seconds is None
            else max_age_seconds
        )
        self.backup_count = (
            DEFAULT_BACKUP_COUNT
            if backup_count is None
            else backup_count
        )

        if self.max_bytes <= 0 or self.max_age_seconds <= 0:
            raise ValueError("Rotation thresholds must be positive.")
        if self.backup_count < 0:
            raise ValueError("backup_count cannot be negative.")

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.log_path.open("a", encoding="utf-8")
        self._last_rotation = time.time()

    def emit(self, record):
        try:
            message = self.format(record) + "\n"
            encoded_size = len(message.encode("utf-8"))

            self.acquire()
            try:
                self._stream.flush()

                size_exceeded = (
                    self.log_path.stat().st_size + encoded_size
                    >= self.max_bytes
                )
                time_exceeded = (
                    time.time() - self._last_rotation
                    >= self.max_age_seconds
                )

                if self.log_path.stat().st_size and (
                    size_exceeded or time_exceeded
                ):
                    self._rotate()

                self._stream.write(message)
                self._stream.flush()
            finally:
                self.release()

        except Exception:
            self.handleError(record)

    def _rotate(self):
        self._stream.close()

        try:
            if self.log_path.exists() and self.log_path.stat().st_size:
                timestamp = time.strftime(
                    "%Y%m%d-%H%M%S",
                    time.localtime(),
                )
                archive = self.log_path.with_name(
                    f"{self.log_path.name}.{timestamp}.rotated"
                )

                suffix = 1
                while archive.exists():
                    archive = self.log_path.with_name(
                        f"{self.log_path.name}.{timestamp}.{suffix}.rotated"
                    )
                    suffix += 1

                self.log_path.rename(archive)

                backups = sorted(
                    self.log_path.parent.glob(
                        f"{self.log_path.name}.*.rotated"
                    ),
                    key=lambda path: path.stat().st_mtime,
                    reverse=True,
                )

                for old_backup in backups[self.backup_count:]:
                    old_backup.unlink()

            self._last_rotation = time.time()

        except OSError:
            logger.exception(
                "Automatic log rotation failed for %s",
                self.log_path,
            )
            raise

        finally:
            self._stream = self.log_path.open("a", encoding="utf-8")

    def close(self):
        self.acquire()
        try:
            if not self._stream.closed:
                self._stream.close()
        finally:
            self.release()
            super().close()


def configure_application_logging():
    """Configure application logging with automatic size/time rotation."""
    log_directory = Path(
        os.environ.get(
            "PACKET_LOG_DIR",
            str(BACKEND_DIR / "logs"),
        )
    ).resolve()

    log_path = log_directory / "application.log"

    handler = SizeAndTimeRotatingHandler(log_path)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        )
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    existing_handler = next(
        (
            item for item in root_logger.handlers
            if getattr(item, "baseFilename", None) == str(log_path)
            or getattr(item, "log_path", None) == log_path
        ),
        None,
    )

    if existing_handler is not None:
        handler.close()
        return existing_handler

    root_logger.addHandler(handler)
    return handler
