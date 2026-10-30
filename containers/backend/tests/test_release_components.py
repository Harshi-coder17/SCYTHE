"""Trusted component loading, numerical parity and image-contract regression."""
import json
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from services import release_components as components
from services.model_features.url_features import FEATURE_NAMES


def bundle(tmp_path, artifact, contract, model_version="test_v1", artifact_name="visual.json"):
    artifact_path = tmp_path / artifact_name
    if isinstance(artifact, dict):
        artifact_path.write_text(json.dumps(artifact))
    else:
        # Native LightGBM tree byte offsets require LF preservation on Windows.
        artifact_path.write_bytes(artifact.encode("utf-8"))
    contract_path = tmp_path / "component.json"
    contract_path.write_text(json.dumps({"version": model_version, "positive_label": 1, **contract}))
    hashes = {path.name: components.digest(path) for path in (artifact_path, contract_path)}
    descriptor = {"model_version": model_version, "artifact_file": artifact_name,
        "artifact_sha256": hashes[artifact_name], "contract_file": contract_path.name,
        "contract_sha256": hashes[contract_path.name]}
    return hashes, descriptor


def test_logistic_probability_matches_sklearn():
    from sklearn.linear_model import LogisticRegression
    rng = np.random.default_rng(42)
    x = rng.normal(size=(40, 512))
    y = np.arange(40) % 2
    fitted = LogisticRegression(C=.1).fit(x, y)
    artifact = {"classes": [0, 1], "coef": fitted.coef_[0].tolist(), "intercept": float(fitted.intercept_[0])}
    predicted = np.asarray([components.linear_probability(artifact, vector) for vector in x])
    np.testing.assert_allclose(predicted, fitted.predict_proba(x)[:, 1], atol=1e-12)
    artifact["intercept"] = 100000
    assert components.linear_probability(artifact, x[0]) == 1
    artifact["intercept"] = -100000
    assert components.linear_probability(artifact, x[0]) == 0


def test_component_hash_changes_fail_closed(tmp_path):
    hashes, descriptor = bundle(tmp_path, {}, {})
    (tmp_path / "visual.json").write_text("tampered")
    result = components.score_components(tmp_path, hashes, {"visual": descriptor}, None, None, tmp_path)
    assert result["visual"]["status"] == "unavailable"
    assert result["visual"]["phishing_probability"] is None
    with pytest.raises(ValueError, match="checksum"):
        components.verify_descriptor(tmp_path, hashes, descriptor)


def test_descriptor_cannot_reference_unverified_file(tmp_path):
    hashes, descriptor = bundle(tmp_path, {}, {})
    with pytest.raises(ValueError, match="checksum"):
        components.verify_descriptor(tmp_path, {}, descriptor)
    descriptor["artifact_file"] = "../outside.json"
    with pytest.raises(ValueError):
        components.verify_descriptor(tmp_path, hashes, descriptor)


def test_native_url_prediction_parity_and_cached_tampering(tmp_path):
    import lightgbm
    from services.model_features.url_features import build_url_feature_vector
    x = np.random.default_rng(42).normal(size=(50, len(FEATURE_NAMES)))
    classifier = lightgbm.LGBMClassifier(n_estimators=3, min_child_samples=2, verbosity=-1).fit(
        x, np.arange(50) % 2, feature_name=list(FEATURE_NAMES))
    hashes, descriptor = bundle(tmp_path, classifier.booster_.model_to_string(),
        {"scoring_backend": "lightgbm_native_booster", "features": list(FEATURE_NAMES)}, artifact_name="url.txt")
    url = "https://example.org/login"
    output = components.score_components(tmp_path, hashes, {"url": descriptor}, url, None, tmp_path)
    expected = classifier.predict_proba(np.asarray([build_url_feature_vector(url)["values"]]))[0, 1]
    assert output["url"]["phishing_probability"] == pytest.approx(expected)
    assert output["url"]["artifact_hashes"] == descriptor
    (tmp_path / "url.txt").write_text("tampered after cache load")
    output = components.score_components(tmp_path, hashes, {"url": descriptor}, url, None, tmp_path)
    assert output["url"]["status"] == "unavailable"


def test_character_url_artifact_prediction_parity_without_pickle(tmp_path):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from services.model_features.url_features import build_url_feature_vector

    urls = [
        "https://example.org/login", "http://secure-example.net/verify", "https://bank.example/signin",
        "http://account-update.example.co.uk/session", "https://docs.example.org/help",
        "http://news.example.net/story", "https://mail.example.com/oauth", "http://shop.example.org/cart",
    ] * 4
    labels = np.arange(len(urls)) % 2
    canonical = [build_url_feature_vector(url)["canonical_url"] for url in urls]
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=100_000,
        sublinear_tf=True, dtype=np.float32, lowercase=True)
    x = vectorizer.fit_transform(canonical)
    model = LogisticRegression(C=1.0, class_weight="balanced", solver="liblinear", random_state=42).fit(x, labels)
    vectorizer_data = {"schema_version": 1, "analyzer": "char", "ngram_range": [3, 5],
        "lowercase": True, "smooth_idf": True, "sublinear_tf": True, "l2_normalized": True,
        "vocabulary": {str(token): int(index) for token, index in vectorizer.vocabulary_.items()},
        "idf": [float(value) for value in vectorizer.idf_]}
    head = {"classes": [0, 1], "coefficients": model.coef_[0].astype(float).tolist(),
        "intercept": float(model.intercept_[0])}
    artifact = tmp_path / "url_head.json"
    vectorizer_path = tmp_path / "url_vectorizer.json"
    metadata_path = tmp_path / "url_metadata.json"
    artifact.write_text(json.dumps(head))
    vectorizer_path.write_text(json.dumps(vectorizer_data))
    metadata_path.write_text(json.dumps({"format": "supplemental-checksum-fixture"}))
    contract = {"version": "url_char_tfidf_v1", "positive_label": 1,
        "feature_contract": {"analyzer": "char", "ngram_range": [3, 5], "lowercase": True,
            "max_features": 100_000, "sublinear_tf": True},
        "scoring_backend": "url_char_tfidf_linear_v1"}
    contract_path = tmp_path / "url_contract.json"
    contract_path.write_text(json.dumps(contract))
    hashes = {path.name: components.digest(path) for path in (artifact, vectorizer_path, metadata_path, contract_path)}
    descriptor = {"model_version": "url_char_tfidf_v1", "artifact_file": artifact.name,
        "artifact_sha256": hashes[artifact.name], "contract_file": contract_path.name,
        "contract_sha256": hashes[contract_path.name], "support_files": [{"role": "vectorizer",
            "file": vectorizer_path.name, "sha256": hashes[vectorizer_path.name]},
            {"role": "metadata", "file": metadata_path.name, "sha256": hashes[metadata_path.name]}]}
    output = components.score_components(tmp_path, hashes, {"url": descriptor}, urls[0], None, tmp_path)
    expected = model.predict_proba(vectorizer.transform([canonical[0]]))[0, 1]
    assert output["url"]["status"] == "observed"
    assert output["url"]["phishing_probability"] == pytest.approx(expected, abs=2e-6)
    hashes[vectorizer_path.name] = "0" * 64
    output = components.score_components(tmp_path, hashes, {"url": descriptor}, urls[0], None, tmp_path)
    assert output["url"]["status"] == "unavailable"
    assert output["url"]["phishing_probability"] is None


def test_standardization_preserves_exact_v2_geometry():
    # Raster coordinate gradients make wrong vertical or horizontal crops visible.
    pixels = np.zeros((802, 1920, 3), dtype=np.uint8)
    pixels[:, :, 0] = np.arange(1920, dtype=np.uint16)[None, :] % 256
    pixels[:, :, 1] = np.arange(802, dtype=np.uint16)[:, None] % 256
    source = Image.fromarray(pixels)
    expected = source.crop((0, 0, 1920, 802)).resize((960, 401), Image.Resampling.LANCZOS)
    np.testing.assert_array_equal(components.standardize(source), expected)
    taller = Image.fromarray(np.tile(np.arange(960, dtype=np.uint16)[:, None, None] % 255, (1, 1280, 3)).astype(np.uint8))
    expected = taller.crop((0, 0, 1280, round(1280 / (960 / 401)))).resize((960, 401), Image.Resampling.LANCZOS)
    np.testing.assert_array_equal(components.standardize(taller), expected)
    with pytest.raises(ValueError, match="near_uniform"):
        components.standardize(Image.new("RGB", (960, 401), "white"))


def source_contract(tmp_path):
    checkpoint = tmp_path / "checkpoints/s0.pt"
    checkpoint.parent.mkdir()
    checkpoint.write_bytes(b"fixture checkpoint")
    package = tmp_path / "vendor/ml-mobileclip/mobileclip"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    source.write_text("# fixture source")
    reference = {"name": "mobileclip_s0", "device": "cpu", "dtype": "float32", "embedding_dimensions": 512,
        "preprocessing_version": components.PREPROCESSING_VERSION, "checkpoint_relative_path": "checkpoints/s0.pt",
        "checkpoint_sha256": components.digest(checkpoint)}
    return {"encoder_ref": reference, "preprocessing_version": components.PREPROCESSING_VERSION,
        "embedding_dimensions": 512, "embedding_normalization": "L2", "selected_representation": "three_crop_mean",
        "vendor_source_sha256": {"mobileclip/__init__.py": components.digest(source)}}


def test_encoder_verifies_source_and_checkpoint_before_cache(tmp_path):
    contract = source_contract(tmp_path)
    components.verify_encoder(contract, tmp_path)
    (tmp_path / "vendor/ml-mobileclip/mobileclip/__init__.py").write_text("# changed")
    with pytest.raises(ValueError, match="source_mismatch"):
        components.verify_encoder(contract, tmp_path)


def test_changed_vendor_tree_requires_fresh_worker(tmp_path, monkeypatch):
    contract = source_contract(tmp_path)
    vendor = (tmp_path / "vendor/ml-mobileclip").resolve()
    monkeypatch.setitem(components._IMPORTED_SOURCE_PINS, str(vendor), "previous-imported-code")
    with pytest.raises(ValueError, match="worker_restart_required"):
        components._load_encoder(contract, tmp_path)
    contract["preprocessing_version"] = "unsupported"
    with pytest.raises(ValueError, match="unsupported_encoder"):
        components.verify_encoder(contract, tmp_path)


def test_visual_scoring_uses_safe_weights_and_descriptor(tmp_path, monkeypatch):
    contract = {"scoring_backend": "json_linear_logistic"}
    hashes, descriptor = bundle(tmp_path, {"classes": [0, 1], "coef": [0.] * 512, "intercept": 0.}, contract)
    monkeypatch.setattr(components, "encode_image", lambda *args: np.full(512, 1 / np.sqrt(512)))
    output = components.score_components(tmp_path, hashes, {"visual": descriptor}, None, Path("fixture.png"), tmp_path)
    assert output["visual"]["phishing_probability"] == .5
    assert output["visual"]["artifact_hashes"] == descriptor
