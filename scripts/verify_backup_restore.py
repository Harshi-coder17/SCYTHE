"""Verify an encrypted backup in a uniquely created disposable PostgreSQL DB.

Plaintext and encryption/database secrets remain inside the worker. Existing
backups are never pruned: the normal backup task receives an isolated directory.
No running application databases are restored into, dropped, or modified.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import uuid

DATABASE_PATTERN = re.compile(r"scythe_restore_verify_[a-f0-9]{32}\Z")
CONTAINER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")

# Executed only inside the trusted worker image. It emits aggregate evidence,
# never archive bytes, SQL data, credentials, key material or subprocess errors.
WORKER_SCRIPT = r'''
import hashlib, json, os, re, stat, subprocess, sys, tempfile
from pathlib import Path
import psycopg2
from psycopg2 import sql
from config import settings
from services.backup_crypto import format_name, verified_plaintext

operation, database, expected_major = sys.argv[1], sys.argv[2], int(sys.argv[3])
if not re.fullmatch(r"scythe_restore_verify_[a-f0-9]{32}", database):
    raise ValueError("Invalid disposable database identity")
base = Path(settings.BACKUP_DIR).resolve()
directory = base / ("restore-verification-" + database.rsplit("_", 1)[1])

def major(command):
    result = subprocess.run([command, "--version"], capture_output=True, check=True, timeout=10)
    match = re.search(rb"PostgreSQL[)] ([0-9]+)", result.stdout)
    if not match:
        raise RuntimeError("PostgreSQL tool version unavailable")
    return int(match.group(1))

def connect(name):
    return psycopg2.connect(host="postgres", port=5432, dbname=name,
                           user="scythe_user", password=settings.SCYTHE_DB_PASSWORD,
                           connect_timeout=10, options="-c statement_timeout=60000")

def inventory(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name")
        names = [row[0] for row in cursor.fetchall()]
        counts = {}
        for name in names:
            cursor.execute(sql.SQL("SELECT count(*) FROM {}.{}").format(sql.Identifier("public"), sql.Identifier(name)))
            counts[name] = cursor.fetchone()[0]
        cursor.execute("SELECT table_name,column_name,ordinal_position,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position")
        columns = cursor.fetchall()
        cursor.execute("SELECT t.relname,c.conname,c.contype,pg_get_constraintdef(c.oid,true) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' ORDER BY t.relname,c.conname")
        constraints = cursor.fetchall()
        cursor.execute("SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY tablename,indexname")
        indexes = cursor.fetchall()
        structure = {'columns': columns, 'constraints': constraints, 'indexes': indexes}
    return {"table_counts": counts, "schema_sha256": hashlib.sha256(json.dumps(structure, separators=(',', ':'), default=str).encode()).hexdigest()}

dump_major, restore_major = major("pg_dump"), major("pg_restore")
if dump_major != expected_major or restore_major != expected_major:
    raise RuntimeError("Dump/restore/server major versions must match")
if not settings.BACKUP_ENCRYPTION_KEY or chr(10) in settings.BACKUP_ENCRYPTION_KEY or chr(13) in settings.BACKUP_ENCRYPTION_KEY:
    raise RuntimeError("A valid local encryption key is required")

if operation == "prepare":
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    from tasks import db_backup
    original_run, original_directory = db_backup.subprocess.run, settings.BACKUP_DIR
    connection = connect("scythe_db")
    try:
        connection.set_session(isolation_level='REPEATABLE READ', readonly=True)
        with connection.cursor() as cursor:
            cursor.execute("SHOW server_version_num")
            server_major = int(cursor.fetchone()[0]) // 10000
            if server_major != expected_major:
                raise RuntimeError("Source server major differs from expected")
            cursor.execute("SELECT pg_export_snapshot()")
            snapshot = cursor.fetchone()[0]
        expected = inventory(connection)
        if not {'users', 'scans', 'incidents'}.issubset(expected['table_counts']):
            raise RuntimeError("Source application schema is incomplete")
        def snapshot_run(command, **kwargs):
            if command and Path(command[0]).name == 'pg_dump':
                command = [*command, '--snapshot=' + snapshot]
            return original_run(command, **kwargs)
        # Process-local overrides preserve the actual backup/encryption task
        # while binding its dump to the same snapshot as expected counts.
        settings.BACKUP_DIR = str(directory)
        db_backup.subprocess.run = snapshot_run
        result = db_backup.db_backup_task.run()
    finally:
        db_backup.subprocess.run = original_run
        settings.BACKUP_DIR = original_directory
        connection.close()
    archive = Path(result['backup_path']).resolve()
    if archive.parent != directory or not archive.name.endswith('.enc') or result.get('pruned_expired_count') != 0:
        raise RuntimeError("Backup isolation or encryption verification failed")
    if stat.S_IMODE(archive.stat().st_mode) != 0o600:
        raise RuntimeError("Encrypted backup permissions are not owner-only")
    if format_name(archive) != "scythe_aes256gcm_v1":
        raise RuntimeError("New backups must use authenticated format v1")
    with archive.open('rb') as stream:
        archive_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    evidence = {**expected, 'archive_name': archive.name, 'archive_sha256': archive_digest,
                'archive_bytes': archive.stat().st_size, 'dump_major': dump_major, 'restore_major': restore_major,
                'server_major': expected_major, 'pruned_existing_backups': 0, 'encrypted': True, 'snapshot_consistent': True,
                'authenticated': True, 'encryption_format': 'scythe_aes256gcm_v1'}
    manifest = directory / 'manifest.json'
    manifest.write_text(json.dumps(evidence))
    manifest.chmod(0o600)
    print(json.dumps(evidence))
elif operation == "restore":
    evidence = json.loads((directory / 'manifest.json').read_text())
    archive = (directory / evidence['archive_name']).resolve()
    if archive.parent != directory or not archive.name.endswith('.enc'):
        raise RuntimeError("Unexpected archive path")
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != evidence['archive_sha256']:
            raise RuntimeError("Encrypted archive checksum mismatch")
    descriptor, pgpass = tempfile.mkstemp(prefix='scythe-restore-', dir='/tmp')
    restore = None
    try:
        escaped = settings.SCYTHE_DB_PASSWORD.replace(chr(92), chr(92) * 2).replace(':', chr(92) + ':')
        with os.fdopen(descriptor, 'w') as stream:
            stream.write('postgres:5432:' + database + ':scythe_user:' + escaped + chr(10))
        os.chmod(pgpass, 0o600)
        environment = os.environ.copy()
        environment['PGPASSFILE'] = pgpass
        # Authentication completes before this context yields any plaintext.
        # Therefore pg_restore never starts for corrupt or wrong-key archives.
        with verified_plaintext(archive, settings.BACKUP_ENCRYPTION_KEY, work_dir='/tmp') as verified_dump:
            with tempfile.TemporaryFile(dir='/tmp') as restore_error:
                restore = subprocess.Popen(['pg_restore', '--host=postgres', '--port=5432', '--username=scythe_user',
                                            '--dbname=' + database, '--no-owner', '--no-privileges', '--exit-on-error'],
                                           stdin=verified_dump, stdout=subprocess.DEVNULL, stderr=restore_error, env=environment)
                if restore.wait(timeout=300):
                    raise RuntimeError("Authenticated restore subprocess failed")
        connection = connect(database)
        try:
            actual = inventory(connection)
            with connection.cursor() as cursor:
                cursor.execute('SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()')
                owner = cursor.fetchone()[0]
        finally:
            connection.close()
        matched = actual == {key: evidence[key] for key in ('table_counts', 'schema_sha256')}
        if not matched or owner != 'scythe_user':
            raise RuntimeError("Restored snapshot schema/counts/owner do not match")
        print(json.dumps({'verified': True, **actual, 'database_owner': owner, 'host_plaintext_created': False,
                          'authenticated_before_restore': True}))
    finally:
        for process in (restore,):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        os.unlink(pgpass)
else:
    raise ValueError("Unknown verification operation")
'''


def command(arguments, *, timeout=600):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Container verification operation failed; raw diagnostics withheld")
    return result.stdout.decode("utf-8")


def worker_call(container, operation, database, major):
    output = command(["docker", "exec", container, "python", "-c", WORKER_SCRIPT, operation, database, str(major)])
    return json.loads(output)


def admin_call(container, operation, database=None):
    if operation == "versions":
        output = command(["docker", "exec", container, "sh", "-c",
                          'export PGPASSWORD="$POSTGRES_PASSWORD"; psql --no-psqlrc -U postgres -d postgres -Atc "SHOW server_version_num" && pg_restore --version'])
        rows = output.strip().splitlines()
        match = re.search(r"PostgreSQL\) (\d+)", rows[-1]) if rows else None
        if not match:
            raise RuntimeError("PostgreSQL reader version unavailable")
        return {"server_major": int(rows[0]) // 10000, "restore_major": int(match.group(1))}
    if not database or not DATABASE_PATTERN.fullmatch(database):
        raise ValueError("Refusing non-disposable database operation")
    if operation == "create":
        script = 'export PGPASSWORD="$POSTGRES_PASSWORD"; exec createdb --username=postgres --maintenance-db=postgres --owner=scythe_user "$1"'
    elif operation == "drop":
        script = 'export PGPASSWORD="$POSTGRES_PASSWORD"; exec dropdb --username=postgres --maintenance-db=postgres --force "$1"'
    else:
        raise ValueError("Unknown administrative operation")
    command(["docker", "exec", container, "sh", "-c", script, "restore-verifier", database], timeout=60)
    return {"success": True}


def verify(worker_container, postgres_container, *, worker=worker_call, admin=admin_call):
    if not all(CONTAINER_PATTERN.fullmatch(value) for value in (worker_container, postgres_container)):
        raise ValueError("Invalid container identity")
    database = "scythe_restore_verify_" + uuid.uuid4().hex
    created = False
    report = {"passed": False, "disposable_database": database, "cleanup_succeeded": False,
              "existing_backups_untouched": True, "host_plaintext_created": False,
              "generated_at_utc": datetime.now(timezone.utc).isoformat()}
    stage = "version_preflight"
    try:
        versions = admin(postgres_container, "versions")
        report["postgres_versions"] = versions
        if versions["server_major"] != versions["restore_major"]:
            raise RuntimeError("Server and archive reader major versions differ")
        stage = "encrypted_snapshot_backup"
        backup = worker(worker_container, "prepare", database, versions["server_major"])
        report["backup"] = backup
        if not backup.get("encrypted") or not backup.get("authenticated") or not backup.get("snapshot_consistent") or backup.get("pruned_existing_backups") != 0:
            raise RuntimeError("Backup encryption/snapshot/isolation verification failed")
        stage = "create_disposable_database"
        admin(postgres_container, "create", database)
        created = True
        stage = "decrypt_restore_verify"
        restored = worker(worker_container, "restore", database, versions["server_major"])
        report["restore"] = restored
        if not restored.get("verified") or not restored.get("authenticated_before_restore"):
            raise RuntimeError("Restored evidence did not verify")
        report["passed"] = True
    except Exception as exc:
        report.update(failure_stage=stage, failure_type=type(exc).__name__,
                      failure="Backup restore verification did not complete; secrets and raw database diagnostics are withheld")
    finally:
        if created:
            try:
                admin(postgres_container, "drop", database)
                report["cleanup_succeeded"] = True
            except Exception:
                report["passed"] = False
                report["cleanup_error"] = "Only the named disposable database needs administrative cleanup"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", default="scythe_celery_worker")
    parser.add_argument("--postgres", default="scythe_postgres")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.worker, args.postgres)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
