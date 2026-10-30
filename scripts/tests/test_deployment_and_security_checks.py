import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


production = load("check_production_config")
security = load("security_scan")


def valid_config():
    env = {"ENVIRONMENT": "production", "REQUIRE_REAL_CERT": "true",
           "SCYTHE_DB_PASSWORD": "db-secret-" + "a" * 32,
           "POSTGRES_ROOT_PASSWORD": "root-secret-" + "b" * 32,
           "REDIS_PASSWORD": "redis-secret-" + "c" * 32,
           "REDIS_SECURITY_PASSWORD": "redis-sec-secret-" + "d" * 32,
           "SANDBOX_RUNNER_SECRET": "runner-secret-" + "e" * 32,
           "BACKUP_ENCRYPTION_KEY": "backup-secret-" + "f" * 32,
           "SHADOW_SCORING_ENABLED": "false",
           "ALLOWED_HOSTS": "scythe-project.com,backend", "CORS_ALLOWED_ORIGINS": "https://scythe-project.com"}
    services = {name: {"environment": copy.deepcopy(env)} for name in production.APP_SERVICES}
    services["postgres"] = {"environment": {"POSTGRES_PASSWORD": env["POSTGRES_ROOT_PASSWORD"]}}
    services["nginx"] = {"environment": {"REQUIRE_REAL_CERT": "true"}, "read_only": True,
        "volumes": [{"type": "bind", "source": "/fixture/certs", "target": "/etc/nginx/certs", "read_only": True}],
        "tmpfs": ["/var/cache/nginx:rw", "/var/run:rw", "/tmp:rw", "/var/log/nginx:rw"]}
    services["scythe_sandbox_runner"] = {"environment": {"ENVIRONMENT": "production", "SANDBOX_IMAGE": "sha256:" + "a" * 64}}
    return {"services": services}


def test_valid_static_production_invariants():
    assert production.validate_config(valid_config()) == []


def test_postgres_superuser_secret_is_read_from_native_compose_environment():
    config = valid_config()
    root_password = config["services"]["backend"]["environment"]["POSTGRES_ROOT_PASSWORD"]
    config["services"]["postgres"]["environment"] = {"POSTGRES_PASSWORD": root_password}
    for service in config["services"].values():
        service.get("environment", {}).pop("POSTGRES_ROOT_PASSWORD", None)
    assert production.validate_config(config) == []


@pytest.mark.parametrize("mutation", [
    lambda c: c["services"]["backend"]["environment"].update(ENVIRONMENT="development"),
    lambda c: c["services"]["celery_worker"]["environment"].update(BACKUP_ENCRYPTION_KEY=""),
    lambda c: c["services"]["nginx"]["tmpfs"].append("/etc/nginx/certs:rw"),
    lambda c: c["services"]["nginx"]["volumes"][0].update(read_only=False),
    lambda c: c["services"]["nginx"].update(tmpfs=["/tmp:rw"]),
    lambda c: c["services"]["backend"]["environment"].update(CORS_ALLOWED_ORIGINS="http://scythe.example.test"),
    lambda c: c["services"]["backend"]["environment"].update(CLAMAV_FAIL_CLOSED="false"),
    lambda c: c["services"]["scythe_sandbox_runner"]["environment"].update(SANDBOX_IMAGE="sandbox:latest"),
])
def test_production_regressions_fail_closed(mutation):
    config = valid_config()
    mutation(config)
    assert production.validate_config(config)


def test_production_rejects_short_or_reused_secrets():
    config = valid_config()
    config["services"]["backend"]["environment"]["REDIS_PASSWORD"] = "too-short"
    assert any("REDIS_PASSWORD" in error for error in production.validate_config(config))
    config = valid_config()
    config["services"]["backend"]["environment"]["REDIS_SECURITY_PASSWORD"] = config["services"]["backend"]["environment"]["REDIS_PASSWORD"]
    assert any("REDIS_SECURITY_PASSWORD" in error for error in production.validate_config(config))


def test_ci_image_gate_tracks_compose_postgres_digest_and_beat_image():
    root = SCRIPTS.parent
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    workflow = (root / ".github/workflows/verify.yml").read_text(encoding="utf-8")
    postgres = next(line.strip().split("image:", 1)[1].strip() for line in compose.splitlines()
                    if "image: postgres:16-alpine@sha256:" in line)
    assert postgres in workflow
    assert "scythe-celery_beat:latest" in workflow
    assert "scythe-celery_shadow_worker:latest" in workflow
    assert "docker compose build backend celery_worker celery_beat celery_shadow_worker" in workflow


def test_python_service_healthchecks_do_not_require_curl():
    root = SCRIPTS.parent
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    dockerfiles = [root / "containers/backend" / name for name in
                   ("Dockerfile", "Dockerfile.worker", "Dockerfile.runner", "Dockerfile.shadow")]
    assert "curl" not in compose
    assert "urllib.request.urlopen('http://127.0.0.1:8000/', timeout=5)" in compose
    assert "urllib.request.urlopen('http://127.0.0.1:8002/health', timeout=5)" in compose
    for dockerfile in dockerfiles:
        content = dockerfile.read_text(encoding="utf-8")
        assert "curl" not in content
    assert "urllib.request.urlopen('http://127.0.0.1:8000/', timeout=5)" in dockerfiles[0].read_text(
        encoding="utf-8")


@pytest.mark.parametrize("origin", [
    "https://different-project.com",
    "https://scythe-project.com/path",
    "https://user@scythe-project.com",
    "https://*.project.test",
    "http://scythe-project.com",
])
def test_production_rejects_mismatched_or_non_origin_cors_values(origin):
    config = valid_config()
    config["services"]["backend"]["environment"]["CORS_ALLOWED_ORIGINS"] = origin
    assert any("CORS_ALLOWED_ORIGINS" in error for error in production.validate_config(config))


@pytest.mark.parametrize("host", [
    "replace-with-real-hostname.example",
    "scythe-project.com/path",
    "127.0.0.1",
    "*.project.test",
    "scythe.example.com",
])
def test_production_rejects_placeholder_or_non_dns_public_host(host):
    config = valid_config()
    config["services"]["backend"]["environment"]["ALLOWED_HOSTS"] = f"{host},backend"
    config["services"]["backend"]["environment"]["CORS_ALLOWED_ORIGINS"] = f"https://{host}"
    assert any("explicit public hostname" in error for error in production.validate_config(config))


def test_hostname_parser_rejects_invalid_unicode_without_crashing():
    assert production.public_hostname("bad\ud800.example.com") is None


def test_production_rejects_enabled_or_unset_experimental_shadow_scoring():
    for value in ("true", "", None):
        config = valid_config()
        env = config["services"]["backend"]["environment"]
        if value is None:
            env.pop("SHADOW_SCORING_ENABLED")
        else:
            env["SHADOW_SCORING_ENABLED"] = value
        assert any("shadow scoring" in error for error in production.validate_config(config))


@pytest.mark.skipif(shutil.which("docker") is None, reason="Requires Compose CLI, no containers are started")
def test_real_production_overlay_merge_uses_dummy_values_and_preserves_tls_tmpfs(tmp_path):
    file = tmp_path / "fixture.env"
    values = {name: f"{name.lower()}-fixture-only-credential-0123456789" for name in (
        "SCYTHE_DB_PASSWORD", "POSTGRES_ROOT_PASSWORD", "REDIS_PASSWORD", "REDIS_SECURITY_PASSWORD",
        "SANDBOX_RUNNER_SECRET", "BACKUP_ENCRYPTION_KEY")}
    values.update(SCYTHE_PUBLIC_HOST="scythe-project.com", SCYTHE_PUBLIC_ORIGIN="https://scythe-project.com")
    file.write_text("\n".join(f"{key}={value}" for key, value in values.items()) + "\n")
    config = production.merged_config(file)
    assert not production.validate_config(config)


def test_security_scan_missing_tools_is_failure_with_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(security.shutil, "which", lambda _name: None)
    monkeypatch.setattr(security.importlib.util, "find_spec", lambda _name: None)
    assert security.main(["--checks", "secrets", "sast", "deps", "images", "--output", str(tmp_path)]) == 1
    report = json.loads((tmp_path / "summary.json").read_text())
    assert not report["passed"]
    assert all(not row["passed"] and row["error"] for row in report["results"])


def test_security_scan_missing_targets_is_failure_even_with_tool_module(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "ROOT", tmp_path)
    monkeypatch.setattr(security.importlib.util, "find_spec", lambda _name: object())
    assert security.main(["--checks", "sast", "deps", "--output", str(tmp_path / "report")]) == 1


def test_security_scan_propagates_nonzero_scanner_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(security.importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setattr(security, "run", lambda *_args, **_kwargs: 1)
    assert security.main(["--checks", "sast", "--output", str(tmp_path)]) == 1
    assert not json.loads((tmp_path / "summary.json").read_text())["passed"]


def test_dependency_gate_includes_model_worker_and_propagates_its_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(security.importlib.util, "find_spec", lambda _name: object())
    commands = []

    def scan(command, **_kwargs):
        commands.append(command)
        target = command[command.index("-r") + 1]
        Path(command[command.index("-o") + 1]).write_text(json.dumps({
            "dependencies": [{"name": "fixture", "version": "1.0", "vulns": []}]}))
        return int(target.endswith("requirements.shadow.txt"))

    monkeypatch.setattr(security, "run", scan)
    assert security.main(["--checks", "deps", "--output", str(tmp_path)]) == 1
    report = json.loads((tmp_path / "summary.json").read_text())
    shadow = next(row for row in report["results"] if row["check"].endswith("requirements.shadow.txt"))
    assert shadow["exit_code"] == 1 and not shadow["passed"]
    assert len(commands) == 4
    for command in commands:
        target = command[command.index("-r") + 1]
        service = command[command.index("--vulnerability-service") + 1]
        assert service == ("osv" if target.endswith("requirements.shadow.txt") else "pypi")


def test_dependency_gate_rejects_successful_scanner_with_skipped_wheel(tmp_path, monkeypatch):
    monkeypatch.setattr(security.importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setattr(security, "REQUIREMENTS", ("containers/backend/requirements.shadow.txt",))

    def scan(command, **_kwargs):
        Path(command[command.index("-o") + 1]).write_text(json.dumps({
            "dependencies": [{"name": "torch", "skip_reason": "Local wheel not found"}]}))
        return 0

    monkeypatch.setattr(security, "run", scan)
    assert security.main(["--checks", "deps", "--output", str(tmp_path)]) == 1
    report = json.loads((tmp_path / "summary.json").read_text())
    assert "torch" in report["results"][0]["error"]
    assert not report["passed"]


def test_secret_snapshot_does_not_copy_ignored_environment_or_external_links(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    (repository / ".gitignore").write_text(".env\n")
    (repository / ".env").write_text("PRIVATE_LOCAL_VALUE=fixture\n")
    (repository / "source.py").write_text("answer = 42\n")
    output = tmp_path / "snapshot"
    output.mkdir()
    monkeypatch.setattr(security, "ROOT", repository)
    security.source_snapshot(output)
    assert (output / "source.py").is_file()
    assert not (output / ".env").exists()
