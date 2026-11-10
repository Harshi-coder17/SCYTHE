import hashlib
import os
from pathlib import Path

import pytest

from services import backup_crypto as crypto


def encrypted(tmp_path):
    source = tmp_path / "fixture.dump"
    source.write_bytes(b"PGDMP" + os.urandom(2 * crypto.CHUNK_BYTES + 17))
    key = "fixture-key-never-a-real-project-secret"
    return source, crypto.encrypt_backup(source, key), key


def test_streaming_authenticated_roundtrip_private_cleanup(tmp_path):
    source, archive, key = encrypted(tmp_path)
    assert crypto.format_name(archive) == "scythe_aes256gcm_v1"
    with crypto.verified_plaintext(archive, key, work_dir=tmp_path) as plaintext:
        assert hashlib.sha256(plaintext.read()).digest() == hashlib.sha256(source.read_bytes()).digest()
        stream = plaintext
    assert stream.closed
    assert set(tmp_path.iterdir()) == {source, archive}


@pytest.mark.parametrize("position", [0, 8, 10, 13, 29, crypto.HEADER.size + 9, -1])
def test_tampering_rejected_before_plaintext_can_reach_database(tmp_path, position):
    _source, archive, key = encrypted(tmp_path)
    raw = bytearray(archive.read_bytes())
    raw[position] ^= 1
    archive.write_bytes(raw)
    database_restore_started = []
    with pytest.raises(crypto.BackupAuthenticationError):
        with crypto.verified_plaintext(archive, key, work_dir=tmp_path):
            database_restore_started.append(True)
    assert not database_restore_started
    assert len(list(tmp_path.iterdir())) == 2


def test_wrong_key_and_truncation_fail_before_yield(tmp_path):
    _source, archive, _key = encrypted(tmp_path)
    with pytest.raises(crypto.BackupAuthenticationError):
        with crypto.verified_plaintext(archive, "wrong-fixture-key", work_dir=tmp_path):
            pytest.fail("Authentication failed but plaintext was yielded")
    archive.write_bytes(archive.read_bytes()[:8])
    with pytest.raises(crypto.BackupAuthenticationError):
        with crypto.verified_plaintext(archive, "fixture", work_dir=tmp_path):
            pytest.fail("Truncated plaintext was yielded")


def test_legacy_requires_explicit_opt_in_and_trusted_external_digest(tmp_path, monkeypatch):
    archive = tmp_path / "legacy.enc"
    archive.write_bytes(b"Salted__" + b"fixture" * 10)
    def never(*_args, **_kwargs):
        pytest.fail("Legacy decryption must not start without verified external hash")
    monkeypatch.setattr(crypto.subprocess, "run", never)
    for options in ({}, {"allow_legacy": True}, {"allow_legacy": True, "expected_legacy_sha256": "0" * 64}):
        with pytest.raises(crypto.BackupAuthenticationError):
            with crypto.verified_plaintext(archive, "fixture", work_dir=tmp_path, **options):
                pytest.fail("Untrusted legacy plaintext was yielded")


def test_encryption_timeout_removes_partial_output(tmp_path, monkeypatch):
    source = tmp_path / "fixture.dump"
    source.write_bytes(b"fixture")
    ticks = iter((0, 10))
    monkeypatch.setattr(crypto.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError):
        crypto.encrypt_backup(source, "fixture", timeout=1)
    assert list(tmp_path.iterdir()) == [source]
