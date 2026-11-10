import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import tasks.db_backup as db_backup
from services.backup_crypto import MAGIC, verified_plaintext


def _configure(monkeypatch, tmp_path: Path, encryption_key: str = "") -> None:
    monkeypatch.setattr(db_backup, "settings", SimpleNamespace(
        BACKUP_DIR=str(tmp_path),
        BACKUP_ENCRYPTION_KEY=encryption_key,
        SCYTHE_DB_PASSWORD="test-db-password",
    ))


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_backup_without_encryption_is_owner_only(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        Path(command[command.index("-f") + 1]).write_bytes(b"pg custom archive")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(db_backup.subprocess, "run", fake_run)
    result = db_backup.db_backup_task.run()

    output = Path(result["backup_path"])
    assert result["status"] == "success"
    assert output.exists() and output.suffix == ".dump"
    if os.name == "posix":
        assert _mode(output) == 0o600
    assert len(calls) == 1
    assert calls[0][0][0] == "pg_dump"


def test_encrypted_backup_is_authenticated_and_keeps_output_owner_only(monkeypatch, tmp_path):
    secret = "test-encryption-secret"
    _configure(monkeypatch, tmp_path, secret)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[0] == "pg_dump":
            Path(command[command.index("-f") + 1]).write_bytes(b"pg custom archive")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(db_backup.subprocess, "run", fake_run)
    result = db_backup.db_backup_task.run()

    output = Path(result["backup_path"])
    assert result["status"] == "success"
    assert output.suffix == ".enc"
    assert output.read_bytes().startswith(MAGIC)
    with verified_plaintext(output, secret, work_dir=tmp_path) as plaintext:
        assert plaintext.read() == b"pg custom archive"
    if os.name == "posix":
        assert _mode(output) == 0o600
    assert len(calls) == 1  # Only pg_dump is a subprocess; no key in argv/stdin/env.
    assert secret not in " ".join(calls[0][0])
    assert not list(tmp_path.glob("*.dump"))


def test_encryption_rejects_multiline_key_without_creating_output(tmp_path):
    source = tmp_path / "input.dump"
    source.write_bytes(b"archive")
    with pytest.raises(ValueError, match="newline"):
        db_backup._encrypt_backup(str(source), "part-one\npart-two")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["input.dump"]
