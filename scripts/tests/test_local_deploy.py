"""Local startup must fail safely without disclosing resolved Compose secrets."""
import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location("local_deploy", Path(__file__).parents[1] / "local_deploy.py")
local = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(local)


def config(host="127.0.0.1", service="nginx"):
    return {"services": {service: {"ports": [{"host_ip": host, "target": 443, "published": "8443"}]}}}


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.0.1", "localhost"])
def test_reject_external_listeners(host):
    with pytest.raises(local.LocalDeploymentError):
        local.validate_local_config(config(host))


def test_reject_internal_published_ports():
    with pytest.raises(local.LocalDeploymentError):
        local.validate_local_config(config(service="postgres"))


def test_allow_loopback_and_extract_port():
    assert local.validate_local_config(config()) == 8443
    assert local.validate_local_config(config("::1")) == 8443


def test_health_and_missing_services():
    healthy = [{"Service": item, "State": "running", "Health": "healthy"} for item in local.REQUIRED]
    assert not local.validate_status(healthy)
    healthy[0]["Health"] = "starting"
    assert local.validate_status(healthy)
    assert len(local.validate_status([])) == len(local.REQUIRED)


def test_parse_compose_json_formats():
    assert local.parse_status('[{"Service":"backend"}]') == [{"Service": "backend"}]
    assert len(local.parse_status('{"Service":"backend"}\n{"Service":"nginx"}')) == 2


def test_docker_failure_does_not_echo_secrets(monkeypatch):
    monkeypatch.setattr(local.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 1, "password=secret", "password=secret"))
    with pytest.raises(local.LocalDeploymentError) as caught:
        local.run_docker("compose", "config")
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("bundle,anchor", [("somewhere", None), (None, "0" * 64)])
def test_release_arguments_must_be_paired(bundle, anchor):
    with pytest.raises(local.LocalDeploymentError, match="Both"):
        local.release_environment(bundle, anchor)


def test_invalid_release_fails_before_activation(tmp_path):
    with pytest.raises(local.LocalDeploymentError, match="Release validation failed"):
        local.release_environment(str(tmp_path), "0" * 64)


def test_release_configuration_is_subprocess_only(tmp_path, monkeypatch):
    original = dict(local.os.environ)
    verifier = SimpleNamespace(verify_release=lambda *a: (tmp_path, {}, {}, {}, {}))
    monkeypatch.setattr(local.importlib.util, "module_from_spec", lambda *a: verifier)
    monkeypatch.setattr(local.importlib.util, "spec_from_file_location", lambda *a: SimpleNamespace(
        loader=SimpleNamespace(exec_module=lambda *a: None)))
    environment = local.release_environment(str(tmp_path), "a" * 64)
    assert environment["MODEL_RELEASE_ENABLED"] == "true"
    assert environment["MODEL_RELEASE_HOST_DIR"] == str(tmp_path)
    assert environment["MODEL_RELEASE_BUNDLE_DIR"] == "/opt/scythe/release"
    assert dict(local.os.environ) == original


def test_release_enabled_without_profile_is_rejected():
    settings = {"services": {"backend": {"environment": {"MODEL_RELEASE_ENABLED": "true"}}}}
    with pytest.raises(local.LocalDeploymentError, match="profile are absent"):
        local.validate_model_config(settings, False)
    with pytest.raises(local.LocalDeploymentError, match="worker profile"):
        local.validate_model_config(settings, True)
    settings["services"]["celery_model_worker"] = {}
    local.validate_model_config(settings, True)


def test_model_worker_must_be_healthy():
    rows = [{"Service": item, "State": "running", "Health": "healthy"} for item in local.REQUIRED]
    assert local.validate_status(rows, models=True)
    rows.append({"Service": "celery_model_worker", "State": "running", "Health": ""})
    assert local.validate_status(rows, models=True)
    rows[-1]["Health"] = "healthy"
    assert not local.validate_status(rows, models=True)


def test_compose_passes_model_profile_and_process_environment(monkeypatch):
    calls = []
    monkeypatch.setattr(local, "run_docker", lambda *a, **kw: calls.append((a, kw)))
    local.compose("config", models=True, environment={"MODEL_RELEASE_ENABLED": "true"})
    assert "--profile" in calls[0][0] and "models" in calls[0][0]
    assert calls[0][1]["environment"]["MODEL_RELEASE_ENABLED"] == "true"
