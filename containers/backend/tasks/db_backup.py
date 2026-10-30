"""
tasks/db_backup.py
==================
Celery periodic task for automated logical PostgreSQL backups (`pg_dump`) with
retention management (`RETENTION_DAYS=7`).

Addresses DevSecOps Review Finding #6:
  `postgres/README.md` documents `pg_dump` commands and retention policy, but
  previously required manual execution via cron or Task Scheduler on the host.
  This task runs inside the `celery_worker` (which now includes `postgresql-client`)
  and executes daily logical backups directly against `postgres:5432`, storing compressed
  dumps in the dedicated `/backups` volume and automatically pruning dumps older than 7 days.
  Avoids exposing credentials by using a temporary `.pgpass` file.
"""

import glob
import logging
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone

from celery_worker import celery
from config import settings
from services.backup_crypto import encrypt_backup

logger = logging.getLogger(__name__)


def _secure_temp_path(directory: str, *, prefix: str, suffix: str) -> str:
    """Create an empty owner-only file and return its path."""
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=directory)
    os.close(fd)
    # mkstemp uses 0600 on POSIX; chmod is retained as a defense-in-depth
    # check and permits this helper's unit tests to run on Windows as well.
    os.chmod(path, 0o600)
    return path


def _encrypt_backup(dump_path: str, encryption_key: str, timeout: int = 300) -> str:
    """Encrypt a dump without exposing its key in process arguments."""
    return str(encrypt_backup(dump_path, encryption_key, timeout=timeout))


@celery.task(
    bind=True,
    name="tasks.db_backup",
    queue="default",
    max_retries=2,
    default_retry_delay=60,
    acks_late=True,
)
def db_backup_task(self, retention_days: int = 7) -> dict:
    """
    Execute pg_dump against the primary Postgres container and clean up backups
    older than retention_days.
    """
    logger.info("[db_backup] Starting automated logical database backup (retention=%d days)", retention_days)

    backup_dir = settings.BACKUP_DIR
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    db_password = getattr(settings, "SCYTHE_DB_PASSWORD", "")
    if not db_password:
        logger.error("[db_backup] SCYTHE_DB_PASSWORD not set — cannot authenticate to postgres")
        raise RuntimeError("SCYTHE_DB_PASSWORD is empty")

    dump_path = _secure_temp_path(
        backup_dir,
        prefix=f"scythe_db_{timestamp}_",
        suffix=".dump",
    )

    # Write .pgpass to /tmp (tmpfs — auto-wiped on container restart) rather than
    # the home directory. If the Celery worker receives SIGKILL mid-task, the
    # `finally` block does not execute and a .pgpass in ~ would persist across
    # restarts with the plaintext password visible on the filesystem.
    pgpass_path = None
    try:
        pgpass_fd, pgpass_path = tempfile.mkstemp(prefix="scythe-backup-pgpass-", suffix=".conf")
        with os.fdopen(pgpass_fd, "w", encoding="utf-8") as f:
            escaped = db_password.replace("\\", "\\\\").replace(":", "\\:")
            f.write(f"postgres:5432:scythe_db:scythe_user:{escaped}\n")
        os.chmod(pgpass_path, 0o600)
    except IOError as e:
        logger.error("[db_backup] Failed to write .pgpass: %s", e)
        raise RuntimeError("Could not secure .pgpass file")

    env = os.environ.copy()
    env["PGPASSFILE"] = pgpass_path

    # Use pg_dump custom format (-F c) for compressed, restorable archives
    cmd = [
        "pg_dump",
        "-h", "postgres",
        "-p", "5432",
        "-U", "scythe_user",
        "-F", "c",
        "-b",
        "-v",
        "-f", dump_path,
        "scythe_db",
    ]

    try:
        subprocess.run(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=300,
        )
        # Database dumps contain sensitive records; do not leave them readable
        # by other users of the mounted backup volume.
        os.chmod(dump_path, 0o600)
        logger.info("[db_backup] Database backup created successfully: %s (%d bytes)", dump_path, os.path.getsize(dump_path))

        # Encrypt at rest (finding #4) if BACKUP_ENCRYPTION_KEY is configured
        enc_key = getattr(settings, "BACKUP_ENCRYPTION_KEY", "")
        if enc_key:
            logger.info("[db_backup] Encrypting backup using authenticated AES-256-GCM format v1")
            enc_path = None
            try:
                enc_path = _encrypt_backup(dump_path, enc_key)
                if os.path.exists(dump_path):
                    os.remove(dump_path)
                dump_path = enc_path
                logger.info("[db_backup] Backup encrypted successfully: %s (%d bytes)", dump_path, os.path.getsize(dump_path))
            except Exception as enc_exc:
                logger.error("[db_backup] Failed to encrypt backup file: %s", type(enc_exc).__name__)
                if os.path.exists(dump_path):
                    try:
                        os.remove(dump_path)
                    except OSError:
                        pass
                if enc_path and os.path.exists(enc_path):
                    try:
                        os.remove(enc_path)
                    except OSError:
                        pass
                raise self.retry(exc=enc_exc)
    except subprocess.CalledProcessError as exc:
        err_msg = exc.stderr.decode(errors="ignore")[:1000]
        logger.error("[db_backup] pg_dump failed (exit code %d): %s", exc.returncode, err_msg)
        if os.path.exists(dump_path):
            try:
                os.remove(dump_path)
            except OSError:
                pass
        raise self.retry(exc=exc)
    except Exception as exc:
        logger.exception("[db_backup] Unexpected error executing pg_dump")
        raise self.retry(exc=exc)
    finally:
        if pgpass_path and os.path.exists(pgpass_path):
            try:
                os.remove(pgpass_path)
            except OSError:
                pass

    # Prune expired backups
    cutoff_time = time.time() - (retention_days * 86400)
    removed_count = 0
    for file_path in glob.glob(os.path.join(backup_dir, "scythe_db_*.dump*")):
        try:
            if os.path.getmtime(file_path) < cutoff_time:
                os.remove(file_path)
                removed_count += 1
                logger.info("[db_backup] Pruned expired backup: %s", file_path)
        except Exception as e:
            logger.warning("[db_backup] Could not check/prune %s: %s", file_path, e)

    return {
        "status": "success",
        "backup_path": dump_path,
        "size_bytes": os.path.getsize(dump_path),
        "pruned_expired_count": removed_count,
    }
