"""Versioned streaming backup encryption with authentication before restore.

Format v1: fixed header (magic/version/KDF rounds/salt/nonce), ciphertext, GCM
tag. The header is authenticated as AAD. Plaintext is never yielded before tag
verification. Legacy OpenSSL CBC requires explicit opt-in plus an independently
trusted ciphertext checksum and is supported only inside the Linux worker.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"SCYTHEBK"
VERSION = 1
ITERATIONS = 600_000
HEADER = struct.Struct(">8sBI16s12s")
TAG_BYTES = 16
CHUNK_BYTES = 1024 * 1024
MAX_PLAINTEXT_BYTES = (1 << 36) - 32


class BackupAuthenticationError(ValueError):
    """Archive authentication failed; no plaintext may reach a restore process."""


def _password(value):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise ValueError("Backup encryption key must be a nonempty bounded string")
    if "\n" in value or "\r" in value:
        raise ValueError("Backup encryption key must not contain newline characters")
    return value.encode("utf-8")


def _key(password, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(password)


def format_name(archive):
    with Path(archive).open("rb") as stream:
        prefix = stream.read(HEADER.size)
    if prefix.startswith(MAGIC) and len(prefix) == HEADER.size:
        magic, version, rounds, _salt, _nonce = HEADER.unpack(prefix)
        if magic == MAGIC and version == VERSION and rounds == ITERATIONS:
            return "scythe_aes256gcm_v1"
    if prefix.startswith(b"Salted__"):
        return "legacy_openssl_aes256cbc"
    raise BackupAuthenticationError("Unsupported or malformed backup format")


def encrypt_backup(source, password, *, timeout=300):
    """Return a newly created 0600 AEAD archive; remove partial output on error."""
    password_bytes = _password(password)
    if type(timeout) not in (int, float) or not 0 < timeout <= 3600:
        raise ValueError("Invalid backup encryption time budget")
    deadline = time.monotonic() + timeout
    source = Path(source)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_PLAINTEXT_BYTES:
        raise ValueError("Backup source must be a bounded regular file")
    salt, nonce = os.urandom(16), os.urandom(12)
    header = HEADER.pack(MAGIC, VERSION, ITERATIONS, salt, nonce)
    encryptor = Cipher(algorithms.AES(_key(password_bytes, salt)), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)
    descriptor, name = tempfile.mkstemp(prefix=source.name + ".", suffix=".scbk1.enc", dir=source.parent)
    destination = Path(name)
    try:
        os.chmod(destination, 0o600)
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as incoming:
            descriptor = None
            output.write(header)
            count = 0
            for block in iter(lambda: incoming.read(CHUNK_BYTES), b""):
                if time.monotonic() >= deadline:
                    raise TimeoutError("Backup encryption time budget expired")
                count += len(block)
                if count > MAX_PLAINTEXT_BYTES:
                    raise ValueError("Backup source grew beyond supported size")
                output.write(encryptor.update(block))
            output.write(encryptor.finalize())
            output.write(encryptor.tag)
            output.flush()
            os.fsync(output.fileno())
        return destination
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        destination.unlink(missing_ok=True)
        raise


def _decrypt_authenticated(source, plaintext, password_bytes):
    size = os.fstat(source.fileno()).st_size
    if not HEADER.size + TAG_BYTES <= size <= HEADER.size + MAX_PLAINTEXT_BYTES + TAG_BYTES:
        raise BackupAuthenticationError("Unsupported encrypted backup size")
    header = source.read(HEADER.size)
    magic, version, rounds, salt, nonce = HEADER.unpack(header)
    if magic != MAGIC or version != VERSION or rounds != ITERATIONS:
        raise BackupAuthenticationError("Unsupported or malformed backup format")
    source.seek(-TAG_BYTES, os.SEEK_END)
    tag = source.read(TAG_BYTES)
    source.seek(HEADER.size)
    decryptor = Cipher(algorithms.AES(_key(password_bytes, salt)), modes.GCM(nonce, tag, min_tag_length=TAG_BYTES)).decryptor()
    decryptor.authenticate_additional_data(header)
    remaining = size - HEADER.size - TAG_BYTES
    while remaining:
        block = source.read(min(CHUNK_BYTES, remaining))
        if not block:
            raise BackupAuthenticationError("Truncated encrypted backup")
        plaintext.write(decryptor.update(block))
        remaining -= len(block)
    try:
        plaintext.write(decryptor.finalize())
    except InvalidTag:
        raise BackupAuthenticationError("Backup authentication failed") from None


def _decrypt_legacy(source, plaintext, password_bytes, expected_sha256):
    if os.name != "posix":
        raise BackupAuthenticationError("Legacy restore is supported only inside the Linux worker")
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise BackupAuthenticationError("Legacy restore requires an independently trusted SHA-256")
    digest = hashlib.sha256()
    for block in iter(lambda: source.read(CHUNK_BYTES), b""):
        digest.update(block)
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise BackupAuthenticationError("Legacy ciphertext does not match the trusted checksum")
    source.seek(0)
    # Existing CBC files have no authentication tag. The trusted external hash
    # is mandatory; a sidecar supplied with untrusted ciphertext is insufficient.
    # Both archive and passphrase use already-open descriptors, avoiding a
    # second path open and keeping key material out of argv/environment.
    with tempfile.TemporaryFile(mode="w+b") as passphrase, tempfile.TemporaryFile(mode="w+b") as errors:
        passphrase.write(password_bytes + b"\n")
        passphrase.seek(0)
        try:
            subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", f"fd:{passphrase.fileno()}"],
                           stdin=source, stdout=plaintext, stderr=errors, pass_fds=(passphrase.fileno(),),
                           timeout=300, check=True)
        except (OSError, subprocess.SubprocessError):
            raise BackupAuthenticationError("Legacy decrypt failed; raw diagnostics withheld") from None


@contextmanager
def verified_plaintext(archive, password, *, work_dir=None, allow_legacy=False, expected_legacy_sha256=None):
    """Yield a private temporary stream only after complete integrity validation.

    Temporary plaintext remains inside the worker and is deleted on every exit.
    No database subprocess should start before this context has yielded.
    """
    password_bytes = _password(password)
    with Path(archive).open("rb") as source, tempfile.TemporaryFile(mode="w+b", dir=work_dir) as plaintext:
        prefix = source.read(8)
        source.seek(0)
        if prefix == MAGIC:
            _decrypt_authenticated(source, plaintext, password_bytes)
        elif prefix == b"Salted__" and allow_legacy is True:
            _decrypt_legacy(source, plaintext, password_bytes, expected_legacy_sha256)
        elif prefix == b"Salted__":
            raise BackupAuthenticationError("Legacy CBC backup requires explicit opt-in and a separately trusted checksum")
        else:
            raise BackupAuthenticationError("Unsupported or malformed backup format")
        plaintext.flush()
        plaintext.seek(0)
        yield plaintext
