from unittest.mock import Mock

from celery.exceptions import SoftTimeLimitExceeded
from PIL import Image
import pytest

from tasks import model_inference as task
from services import model_release, release_components


@pytest.fixture
def configured(monkeypatch, tmp_path):
    monkeypatch.setattr(task.settings, "MODEL_RELEASE_ENABLED", True)
    monkeypatch.setattr(task.settings, "MODEL_RELEASE_BUNDLE_DIR", str(tmp_path))
    monkeypatch.setattr(task.settings, "MODEL_RELEASE_CHECKSUMS_SHA256", "a" * 64)
    release = {"supported_paths": ["quick_url", "deep_url"], "model_version": "qualified-software-fixture"}
    contract = {"features": [{"name": "one"}], "components_by_path": {
        "quick_url": {"url": {}}, "deep_url": {"url": {}, "visual": {}}}}
    verify = Mock(return_value=(tmp_path, release, contract, {}, {}))
    monkeypatch.setattr(task, "verify_release", verify)
    return verify


def test_disabled_warmup_never_loads_models(monkeypatch):
    monkeypatch.setattr(task.settings, "MODEL_RELEASE_ENABLED", False)
    verify = Mock(side_effect=AssertionError("must not load"))
    monkeypatch.setattr(task, "verify_release", verify)
    assert task.warm_model_release_task.run() == {"status": "unavailable", "error_reason": "disabled"}
    verify.assert_not_called()


def test_tampered_or_unqualified_bundle_is_rejected(configured):
    configured.side_effect = task.ReleaseUnavailable("checksum_mismatch")
    assert task.warm_model_release_task.run() == {"status": "unavailable", "error_reason": "checksum_mismatch"}


@pytest.mark.parametrize("exception,reason", [(RuntimeError("private details"), "warmup_failed"),
                                             (SoftTimeLimitExceeded(), "timeout")])
def test_warmup_failure_is_bounded(configured, monkeypatch, exception, reason):
    monkeypatch.setattr(release_components, "score_components", Mock(side_effect=exception))
    assert task.warm_model_release_task.run() == {"status": "unavailable", "error_reason": reason}


def test_missing_component_is_not_a_successful_warmup(configured, monkeypatch):
    monkeypatch.setattr(release_components, "score_components", Mock(return_value={}))
    assert task.warm_model_release_task.run()["error_reason"] == "warmup_failed"


def test_disabled_admin_command_does_not_enqueue(monkeypatch, capsys):
    monkeypatch.setattr(task.settings, "MODEL_RELEASE_ENABLED", False)
    dispatch = Mock(side_effect=AssertionError("must not enqueue"))
    monkeypatch.setattr(task.warm_model_release_task, "apply_async", dispatch)
    assert task.warm_admin_command() == 1
    assert '"disabled"' in capsys.readouterr().out
    dispatch.assert_not_called()


def test_admin_command_waits_for_actual_models_child(configured, monkeypatch, capsys):
    dispatched = Mock()
    dispatched.get.return_value = {"status": "warmed", "worker_child_pid": 123}
    dispatch = Mock(return_value=dispatched)
    monkeypatch.setattr(task.warm_model_release_task, "apply_async", dispatch)
    assert task.warm_admin_command() == 0
    dispatch.assert_called_once_with(queue="models")
    dispatched.get.assert_called_once_with(timeout=610)
    assert '"worker_child_pid": 123' in capsys.readouterr().out


def test_warmup_uses_neutral_local_fixture_and_same_child_caches(configured, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", Mock(side_effect=AssertionError("no network")))
    monkeypatch.setattr(socket, "getaddrinfo", Mock(side_effect=AssertionError("no DNS")))
    seen_images = []

    def score(_root, _hashes, requirements, url, image, _encoder):
        assert url == "https://example.invalid/"
        with Image.open(image) as fixture:
            assert fixture.size == (960, 401) and fixture.getpixel((0, 0)) == (127, 127, 127)
        seen_images.append(image)
        return {name: {"status": "observed"} for name in requirements}

    monkeypatch.setattr(release_components, "score_components", score)
    model = Mock()
    model.predict.return_value = [0.5]
    loader = Mock(return_value=model)
    monkeypatch.setattr(model_release, "_load_native", loader)
    result = task.warm_model_release_task.run()
    assert result["status"] == "warmed" and result["warmed_paths"] == ["quick_url", "deep_url"]
    assert result["worker_child_pid"] > 0
    assert not ({"probability", "risk_score", "risk_level", "scan_id"} & result.keys())
    assert configured.call_count == 2 and loader.call_count == model.predict.call_count == 2
    assert all(not path.exists() for path in seen_images)
    assert task.warm_model_release_task.soft_time_limit == 540
    assert task.warm_model_release_task.time_limit == 600
    assert task.warm_model_release_task.reject_on_worker_lost is False
    assert task.model_inference_task.soft_time_limit == 55
    assert task.model_inference_task.time_limit == 60
