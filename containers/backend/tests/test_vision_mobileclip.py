"""
Unit tests for MobileCLIP Visual Scoring Integration in SCYTHE.
Tests screenshot normalization, model resolution/loading, probability inference,
and graceful fallbacks when images, models, or dependencies are absent.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PIL import Image, ImageDraw

from ai_engine.vision import (
    normalize_screenshot,
    score_screenshot_mobileclip,
    _resolve_mobileclip_paths,
    _reset_mobileclip_cache,
)
from config import settings


def _create_sample_image(path: Path, width: int = 960, height: int = 500, solid_color=None):
    """Generate a test image with sufficient pixel variance or solid color."""
    img = Image.new("RGB", (width, height), color=solid_color or (100, 150, 200))
    if solid_color is None:
        draw = ImageDraw.Draw(img)
        # Add high contrast patterns to avoid near_uniform_image check
        for i in range(0, width, 40):
            draw.line([(i, 0), (i, height)], fill=(255, 0, (i * 3) % 256), width=5)
        draw.rectangle([50, 50, 300, 200], fill=(0, 255, 0))
        draw.text((60, 60), "Login Credentials Verification", fill=(0, 0, 0))
    img.save(path, format="PNG")
    return path


def test_normalize_screenshot_valid(tmp_path):
    img_path = tmp_path / "valid.png"
    _create_sample_image(img_path, width=800, height=600)
    with Image.open(img_path) as img:
        normalized = normalize_screenshot(img)
        assert normalized.size == (960, 401)
        assert normalized.mode == "RGB"


def test_normalize_screenshot_incompatible_viewport(tmp_path):
    img_path = tmp_path / "small.png"
    _create_sample_image(img_path, width=300, height=200)
    with Image.open(img_path) as img:
        with pytest.raises(ValueError, match="incompatible_viewport"):
            normalize_screenshot(img)


def test_normalize_screenshot_near_uniform(tmp_path):
    img_path = tmp_path / "uniform.png"
    _create_sample_image(img_path, width=600, height=400, solid_color=(255, 255, 255))
    with Image.open(img_path) as img:
        with pytest.raises(ValueError, match="near_uniform_image"):
            normalize_screenshot(img)


def test_score_screenshot_missing_image_path():
    result = score_screenshot_mobileclip(None)
    assert result["score"] is None
    assert result["status"] == "UNAVAILABLE"
    assert result["visual_phishing_probability"] is None

    result_empty = score_screenshot_mobileclip("")
    assert result_empty["score"] is None
    assert result_empty["status"] == "UNAVAILABLE"


def test_score_screenshot_nonexistent_file(tmp_path):
    missing_file = tmp_path / "does_not_exist.png"
    result = score_screenshot_mobileclip(missing_file)
    assert result["score"] is None
    assert result["status"] == "UNAVAILABLE"
    assert result["visual_phishing_probability"] is None


def test_score_screenshot_corrupted_file(tmp_path):
    corrupt_file = tmp_path / "corrupted.png"
    corrupt_file.write_bytes(b"not an actual png or jpeg byte sequence")
    result = score_screenshot_mobileclip(corrupt_file)
    assert result["score"] is None
    assert result["status"] == "UNAVAILABLE"
    assert result["visual_phishing_probability"] is None


def test_score_screenshot_missing_model_fallback(tmp_path):
    _reset_mobileclip_cache()
    img_path = tmp_path / "test.png"
    _create_sample_image(img_path)

    with patch("ai_engine.vision._resolve_mobileclip_paths", return_value=(None, None, None, None)):
        result = score_screenshot_mobileclip(img_path)
        assert result["score"] is None
        assert result["status"] == "UNAVAILABLE"
        assert result["visual_phishing_probability"] is None


def test_mobileclip_disabled_by_default_is_unavailable(tmp_path, monkeypatch):
    _reset_mobileclip_cache()
    img_path = _create_sample_image(tmp_path / "disabled.png")
    monkeypatch.setattr(settings, "MOBILECLIP_ENABLED", False)

    with patch("ai_engine.vision._resolve_mobileclip_paths", side_effect=AssertionError("must stay disabled")):
        result = score_screenshot_mobileclip(img_path)

    assert result["status"] == "UNAVAILABLE"
    assert result["score"] is None
    assert result["reason"] == "mobileclip_disabled"


def test_mobileclip_paths_come_from_configured_runtime_assets(tmp_path, monkeypatch):
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    (artifact_dir / "classifier.joblib").write_bytes(b"test fixture")
    checkpoint = tmp_path / "mobileclip_s0.pt"
    checkpoint.write_bytes(b"checkpoint fixture")
    vendor = tmp_path / "vendor"
    (vendor / "mobileclip").mkdir(parents=True)
    (vendor / "mobileclip" / "__init__.py").write_text("", encoding="utf-8")

    monkeypatch.setattr(settings, "MOBILECLIP_ARTIFACT_DIR", str(artifact_dir))
    monkeypatch.setattr(settings, "MOBILECLIP_CHECKPOINT_PATH", str(checkpoint))
    monkeypatch.setattr(settings, "MOBILECLIP_VENDOR_DIR", str(vendor))

    resolved_artifact, resolved_checkpoint, resolved_vendor, dependencies = _resolve_mobileclip_paths()

    assert resolved_artifact == artifact_dir.resolve()
    assert resolved_checkpoint == checkpoint.resolve()
    assert resolved_vendor == vendor.resolve()
    assert dependencies is None


def test_score_screenshot_mocked_model_inference(tmp_path):
    torch = pytest.importorskip("torch")
    _reset_mobileclip_cache()
    img_path = tmp_path / "sample.png"
    _create_sample_image(img_path)

    mock_classifier = MagicMock()
    mock_classifier.predict_proba.return_value = [[0.15, 0.85]]
    mock_classifier.classes_ = [0, 1]

    mock_encoder = MagicMock()
    mock_preprocess = MagicMock()

    dummy_tensor = torch.zeros(1, 3, 256, 256)
    mock_preprocess.return_value = dummy_tensor[0]
    mock_encoder.encode_image.return_value = torch.ones(1, 512)

    meta = {
        "model_version": "mobileclip_v1",
        "threshold": 0.433438,
        "artifact_dir": str(tmp_path),
        "checkpoint_path": str(tmp_path / "mobileclip_s0.pt"),
    }

    with patch("ai_engine.vision._get_or_load_mobileclip", return_value=(mock_classifier, mock_encoder, mock_preprocess, meta)):
        result = score_screenshot_mobileclip(img_path)

        assert result["status"] == "OBSERVED"
        assert result["score"] == pytest.approx(0.85)
        assert result["visual_phishing_probability"] == pytest.approx(0.85)
        assert result["classification"] == 1
        assert result["model_version"] == "mobileclip_v1"
        assert result["threshold"] == pytest.approx(0.433438)


def test_score_screenshot_inference_exception_graceful_fallback(tmp_path):
    torch = pytest.importorskip("torch")
    _reset_mobileclip_cache()
    img_path = tmp_path / "sample.png"
    _create_sample_image(img_path)

    mock_classifier = MagicMock()
    mock_classifier.predict_proba.side_effect = RuntimeError("Inference tensor shape mismatch")

    mock_encoder = MagicMock()
    mock_preprocess = MagicMock()
    mock_preprocess.return_value = torch.zeros(3, 256, 256)
    mock_encoder.encode_image.return_value = torch.ones(1, 512)

    meta = {"model_version": "mobileclip_v1", "threshold": 0.433438}

    with patch("ai_engine.vision._get_or_load_mobileclip", return_value=(mock_classifier, mock_encoder, mock_preprocess, meta)):
        result = score_screenshot_mobileclip(img_path)
        assert result["score"] is None
        assert result["status"] == "UNAVAILABLE"
        assert result["visual_phishing_probability"] is None


def test_score_screenshot_real_model_inference():
    """Verify live inference against actual model artifact if present."""
    _reset_mobileclip_cache()
    if not settings.MOBILECLIP_ENABLED:
        pytest.skip("Experimental MobileCLIP scoring is disabled by default")
    artifact_dir, checkpoint_path, vendor_dir, _ = _resolve_mobileclip_paths()
    if not (artifact_dir and checkpoint_path and vendor_dir):
        pytest.skip("Local MobileCLIP artifacts/checkpoints not found")

    preview_path = artifact_dir / "preprocessing_preview.jpg"
    if not preview_path.is_file():
        pytest.skip("Sample preview image not found for live inference test")

    result = score_screenshot_mobileclip(preview_path)
    assert result["status"] == "OBSERVED"
    assert isinstance(result["score"], float)
    assert 0.0 <= result["score"] <= 1.0
    assert result["visual_phishing_probability"] == result["score"]
    assert result["model_version"] == "mobileclip_v1"
    assert "threshold" in result


def test_browser_features_task_integration(tmp_path):
    """Verify tasks.browser_features writes visual_phishing_probability to browser_features.json."""
    from tasks.browser_features import browser_features_task
    scan_id = "12345678-1234-4234-a234-123456789abc"
    scan_dir = tmp_path / scan_id
    scan_dir.mkdir(parents=True)

    img_path = scan_dir / "browser.png"
    _create_sample_image(img_path)
    (scan_dir / "browser.html").write_text("<html><body>Test page</body></html>")

    mock_score = {
        "score": 0.72,
        "status": "OBSERVED",
        "visual_phishing_probability": 0.72,
        "metadata": {"model_version": "mobileclip_v1"},
    }

    with patch("tasks.browser_features.settings.SHARED_DIR", str(tmp_path)), \
         patch("tasks.browser_features._mark_status"), \
         patch("tasks.browser_features._already_finalized", return_value=False), \
         patch("tasks.browser_features.extract_text", return_value="login text"), \
         patch("tasks.browser_features.analyze_screenshot", return_value={"logo": None, "labels": []}), \
         patch("tasks.browser_features.extract_features", return_value={"forms": 1}), \
         patch("tasks.browser_features.score_screenshot_mobileclip", return_value=mock_score), \
         patch("tasks.sandbox_analysis.sandbox_analysis_task.delay"), \
         patch("tasks.consistency.consistency_task.delay"):

        result = browser_features_task.run(scan_id, dispatch_next=False)
        assert result["status"] == "browser_features_done"

        out_json_path = scan_dir / "browser_features.json"
        assert out_json_path.is_file()
        data = json.loads(out_json_path.read_text())

        assert "visual_phishing_probability" in data
        assert data["visual_phishing_probability"] == pytest.approx(0.72)
        assert "visual_score" in data
        assert data["visual_score"]["status"] == "OBSERVED"
