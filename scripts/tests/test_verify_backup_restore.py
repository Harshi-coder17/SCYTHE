import ast
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "verify_backup_restore.py"
spec = importlib.util.spec_from_file_location("verify_backup_restore", SOURCE)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def interfaces(*, failure=None):
    calls = []

    def admin(container, operation, database=None):
        calls.append(("admin", operation, database))
        if failure == operation:
            raise RuntimeError("secret diagnostic which must not be emitted")
        return {"server_major": 16, "restore_major": 16} if operation == "versions" else {"success": True}

    def worker(container, operation, database, major):
        calls.append(("worker", operation, database))
        assert major == 16
        if failure == operation:
            raise RuntimeError("secret diagnostic which must not be emitted")
        return ({"encrypted": True, "authenticated": True, "snapshot_consistent": True, "pruned_existing_backups": 0,
                 "dump_major": 16, "restore_major": 16} if operation == "prepare" else {"verified": True, "authenticated_before_restore": True})

    return calls, admin, worker


def test_success_drops_only_new_unique_disposable_database_and_keeps_evidence():
    calls, admin, worker = interfaces()
    result = backup.verify("scythe_celery_worker", "scythe_postgres", worker=worker, admin=admin)
    assert result["passed"] and result["cleanup_succeeded"]
    assert result["existing_backups_untouched"] and not result["host_plaintext_created"]
    database = result["disposable_database"]
    assert backup.DATABASE_PATTERN.fullmatch(database)
    assert [(kind, operation) for kind, operation, _ in calls] == [
        ("admin", "versions"), ("worker", "prepare"), ("admin", "create"),
        ("worker", "restore"), ("admin", "drop")]
    assert {identity for _, _, identity in calls if identity} == {database}
    assert backup.verify("worker", "postgres", worker=worker, admin=admin)["disposable_database"] != database


@pytest.mark.parametrize("failure", ["versions", "prepare", "create"])
def test_precreation_failures_never_drop_a_database_or_expose_diagnostics(failure):
    calls, admin, worker = interfaces(failure=failure)
    result = backup.verify("worker", "postgres", worker=worker, admin=admin)
    assert not result["passed"]
    assert not any(operation == "drop" for _, operation, _ in calls)
    assert "secret diagnostic" not in json.dumps(result)


def test_restore_failure_always_cleans_created_database():
    calls, admin, worker = interfaces(failure="restore")
    result = backup.verify("worker", "postgres", worker=worker, admin=admin)
    assert not result["passed"] and result["cleanup_succeeded"]
    assert calls[-1] == ("admin", "drop", result["disposable_database"])


def test_cleanup_failure_is_not_reported_as_success():
    _, admin, worker = interfaces(failure="drop")
    result = backup.verify("worker", "postgres", worker=worker, admin=admin)
    assert not result["passed"] and not result["cleanup_succeeded"]
    assert result["cleanup_error"]


def test_version_mismatch_fails_before_any_backup_or_database_change():
    calls = []
    result = backup.verify("worker", "postgres", admin=lambda *_args: {"server_major": 16, "restore_major": 17},
                           worker=lambda *_args: calls.append("unexpected"))
    assert not result["passed"] and result["failure_stage"] == "version_preflight"
    assert not calls


def test_non_disposable_database_names_and_container_options_are_rejected():
    with pytest.raises(ValueError, match="non-disposable"):
        backup.admin_call("postgres", "drop", "scythe_db")
    with pytest.raises(ValueError, match="Invalid container"):
        backup.verify("--privileged", "postgres")


def test_nonzero_commands_do_not_echo_stderr_or_dump_output(monkeypatch):
    monkeypatch.setattr(backup.subprocess, "run", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 1, b"private raw SQL", b"private credentials"))
    with pytest.raises(RuntimeError) as error:
        backup.command(["docker", "fixture"])
    assert "private" not in str(error.value)


def test_embedded_worker_script_compiles_and_authenticates_before_restore():
    tree = ast.parse(backup.WORKER_SCRIPT)
    arguments = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    assert "pg_export_snapshot()" in backup.WORKER_SCRIPT
    assert "--snapshot=" in arguments
    assert "verified_plaintext" in backup.WORKER_SCRIPT
    assert "scythe_aes256gcm_v1" in arguments
    assert "--no-owner" in arguments and "--no-privileges" in arguments
    assert "-pass:" not in backup.WORKER_SCRIPT
    assert "db_backup.db_backup_task.run()" in backup.WORKER_SCRIPT


def test_unauthenticated_archive_cannot_start_database_restore():
    calls, admin, _worker = interfaces()
    def old_worker(*_args):
        return {"encrypted": True, "snapshot_consistent": True, "pruned_existing_backups": 0}
    result = backup.verify("worker", "postgres", worker=old_worker, admin=admin)
    assert not result["passed"]
    assert result["failure_stage"] == "encrypted_snapshot_backup"
    assert not any(operation == "create" for _, operation, _ in calls)
