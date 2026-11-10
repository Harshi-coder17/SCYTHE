"""Checksum-bound native URL and safe linear visual release components.

Research scripts and pickle classifiers are never imported by this worker.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import sys

from services.model_features.url_features import (
    FEATURE_NAMES, FEATURE_NAMES_V1, FEATURE_NAMES_V2, build_url_feature_vector
)

PREPROCESSING_VERSION = "dataset-960x401-topcrop-apple-mobileclip-s0-resize256-center256-totensor-fp32-v1"
_NATIVE_CACHE = {}
_ENCODER_CACHE = {}
_IMPORTED_SOURCE_PINS = {}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


def _contained(root, name):
    if not isinstance(name, str) or not name or "\\" in name or Path(name).is_absolute():
        raise ValueError("invalid_component_path")
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("missing_component_artifact")
    return path


def verify_descriptor(root, hashes, descriptor):
    for field in ("artifact", "contract"):
        name = descriptor.get(f"{field}_file")
        expected = descriptor.get(f"{field}_sha256")
        if not expected or hashes.get(name) != expected:
            raise ValueError("component_checksum_mismatch")
        if digest(_contained(root, name)) != expected:
            raise ValueError("component_checksum_mismatch")
    support_files = descriptor.get("support_files", [])
    if not isinstance(support_files, list):
        raise ValueError("component_contract_mismatch")
    support_names = set()
    for item in support_files:
        if not isinstance(item, dict):
            raise ValueError("component_contract_mismatch")
        name, expected, role = item.get("file"), item.get("sha256"), item.get("role")
        if (not isinstance(role, str) or not role
                or name in support_names or not expected
                or hashes.get(name) != expected or digest(_contained(root, name)) != expected):
            raise ValueError("component_checksum_mismatch")
        support_names.add(name)
    contract = json.loads(_contained(root, descriptor["contract_file"]).read_text(encoding="utf-8"))
    if contract.get("version") != descriptor.get("model_version") or contract.get("positive_label") != 1:
        raise ValueError("component_contract_mismatch")
    return contract


def standardize(image):
    """Exact v2 input preparation: top crop, centered horizontal crop, LANCZOS."""
    from PIL import Image, ImageStat
    rgb = image.convert("RGB")
    if rgb.width < 400 or rgb.height < 250:
        raise ValueError("incompatible_viewport")
    width, height = rgb.size
    target_ratio = 960 / 401
    if width / height < target_ratio:
        height = round(width / target_ratio)
        rgb = rgb.crop((0, 0, width, height))
    else:
        width = round(height * target_ratio)
        left = (rgb.width - width) // 2
        rgb = rgb.crop((left, 0, left + width, height))
    rgb = rgb.resize((960, 401), Image.Resampling.LANCZOS)
    if ImageStat.Stat(rgb.convert("L")).stddev[0] < 2.0:
        raise ValueError("near_uniform_image")
    return rgb


def verify_encoder(contract, source_root):
    """Rehash checkpoint and vendor package before every use, including cache hits."""
    reference = contract.get("encoder_ref", {})
    if (reference.get("name") != "mobileclip_s0" or reference.get("device") != "cpu"
            or reference.get("dtype") != "float32" or reference.get("embedding_dimensions") != 512
            or reference.get("preprocessing_version") != PREPROCESSING_VERSION
            or contract.get("preprocessing_version") != PREPROCESSING_VERSION
            or contract.get("embedding_dimensions") != 512 or contract.get("embedding_normalization") != "L2"
            or contract.get("selected_representation") not in {"center", "three_crop_mean"}):
        raise ValueError("unsupported_encoder_contract")
    source_root = Path(source_root).resolve()
    checkpoint = _contained(source_root, reference.get("checkpoint_relative_path"))
    if digest(checkpoint) != reference.get("checkpoint_sha256"):
        raise ValueError("encoder_checksum_mismatch")
    vendor = source_root / "vendor/ml-mobileclip"
    expected = contract.get("vendor_source_sha256")
    if not isinstance(expected, dict) or not expected:
        raise ValueError("missing_encoder_source_pins")
    actual_paths = {path.relative_to(vendor).as_posix() for path in (vendor / "mobileclip").rglob("*")
                    if path.is_file() and path.suffix in {".py", ".json"}}
    if actual_paths != set(expected):
        raise ValueError("encoder_source_mismatch")
    for name, checksum in expected.items():
        if digest(_contained(vendor, name)) != checksum:
            raise ValueError("encoder_source_mismatch")
    return reference, checkpoint, vendor


def _load_encoder(contract, source_root):
    reference, checkpoint, vendor = verify_encoder(contract, source_root)
    source_pin = hashlib.sha256(json.dumps(contract["vendor_source_sha256"], sort_keys=True).encode()).hexdigest()
    if str(vendor) in _IMPORTED_SOURCE_PINS and _IMPORTED_SOURCE_PINS[str(vendor)] != source_pin:
        # Python caches imported modules independently of our model cache. A new
        # vendor tree at the same path therefore requires a fresh worker process.
        raise ValueError("encoder_worker_restart_required")
    key = (str(vendor), reference["checkpoint_sha256"], source_pin)
    if key not in _ENCODER_CACHE:
        import torch
        # The path is locally configured; every imported source was pinned above.
        sys.path.insert(0, str(vendor))
        try:
            mobileclip = importlib.import_module("mobileclip")
            if Path(mobileclip.__file__).resolve() != (vendor / "mobileclip/__init__.py").resolve():
                raise ValueError("encoder_import_mismatch")
            _IMPORTED_SOURCE_PINS[str(vendor)] = source_pin
            torch.set_num_threads(min(8, os.cpu_count() or 1))
            encoder, _, preprocess = mobileclip.create_model_and_transforms(
                "mobileclip_s0", pretrained=str(checkpoint), reparameterize=True, device="cpu")
        finally:
            sys.path.remove(str(vendor))
        encoder.eval()
        for parameter in encoder.parameters():
            parameter.requires_grad_(False)
        _ENCODER_CACHE[key] = encoder, preprocess
    return _ENCODER_CACHE[key]


def encode_image(image_path, contract, encoder_source_root):
    import numpy as np
    import torch
    import torch.nn.functional as functional
    from PIL import Image
    from torchvision.transforms import InterpolationMode, functional as transforms

    if image_path is None or not Path(image_path).is_file():
        raise ValueError("missing_screenshot")
    with Image.open(image_path) as image:
        image = standardize(image)
    encoder, preprocess = _load_encoder(contract, encoder_source_root)
    if contract["selected_representation"] == "center":
        tensors = [preprocess(image)]
    else:
        resized = transforms.resize(image, 256, interpolation=InterpolationMode.BILINEAR)
        left = transforms.crop(resized, 0, 0, 256, 256)
        right = transforms.crop(resized, 0, resized.width - 256, 256, 256)
        tensors = [preprocess(left), preprocess(image), preprocess(right)]
    with torch.inference_mode():
        vectors = functional.normalize(encoder.encode_image(torch.stack(tensors).float()).float(), dim=-1).cpu().numpy()
    vector = vectors.mean(axis=0)
    norm = float(np.linalg.norm(vector))
    if vector.shape != (512,) or not np.isfinite(vector).all() or norm <= 0:
        raise ValueError("invalid_embedding")
    return (vector / norm).astype(np.float32)


def linear_probability(artifact, vector):
    import numpy as np
    if artifact.get("classes") != [0, 1]:
        raise ValueError("visual_label_orientation")
    coefficient = np.asarray(artifact.get("coef"), dtype=np.float64)
    vector = np.asarray(vector, dtype=np.float64)
    intercept = artifact.get("intercept")
    if (coefficient.shape != (512,) or vector.shape != (512,)
            or not np.isfinite(coefficient).all() or not np.isfinite(vector).all()
            or isinstance(intercept, bool) or not isinstance(intercept, (int, float))
            or not math.isfinite(intercept)):
        raise ValueError("invalid_visual_head")
    score = float(coefficient @ vector + intercept)
    if not math.isfinite(score):
        raise ValueError("invalid_visual_probability")
    # Stable sigmoid for arbitrarily large finite model logits.
    return 1 / (1 + math.exp(-score)) if score >= 0 else math.exp(score) / (1 + math.exp(score))


def _url_score(root, descriptor, contract, raw_url):
    contract_features = tuple(contract.get("features", ()))
    observation = build_url_feature_vector(raw_url, feature_names=contract_features)
    if observation.get("status") != "observed":
        raise ValueError("invalid_http_url")
    path = _contained(root, descriptor["artifact_file"])
    key = (str(path), descriptor["artifact_sha256"])
    backend = contract.get("scoring_backend")
    if backend == "lightgbm_native_booster":
        import lightgbm
        import numpy as np
        if contract_features not in (FEATURE_NAMES_V1, FEATURE_NAMES_V2, FEATURE_NAMES):
            raise ValueError("url_contract_mismatch")
        if key not in _NATIVE_CACHE:
            model = lightgbm.Booster(model_file=str(path))
            if (model.num_feature() != len(contract_features) or tuple(model.feature_name()) != contract_features
                    or not str(model.dump_model().get("objective", "")).startswith("binary")):
                raise ValueError("url_model_mismatch")
            _NATIVE_CACHE[key] = model
        values = np.asarray([observation["values"]], dtype=np.float64)
        probabilities = np.asarray(_NATIVE_CACHE[key].predict(values, num_threads=1), dtype=np.float64)
        if probabilities.shape != (1,):
            raise ValueError("invalid_url_probability")
        return float(probabilities[0])
    if backend == "url_char_tfidf_linear_v1":
        support = [item for item in descriptor.get("support_files", []) if item.get("role") == "vectorizer"]
        if len(support) != 1 or contract.get("version") != "url_char_tfidf_v1":
            raise ValueError("url_contract_mismatch")
        vectorizer = json.loads(_contained(root, support[0]["file"]).read_text(encoding="utf-8"))
        head = json.loads(path.read_text(encoding="utf-8"))
        return char_tfidf_probability(
            vectorizer, head, observation["canonical_url"],
            contract.get("feature_contract"),
        )
    raise ValueError("url_contract_mismatch")


def char_tfidf_probability(vectorizer, head, canonical_url, feature_contract=None):
    """Apply the pinned char 3–5 TF-IDF and logistic head without sklearn or pickle."""
    import numpy as np
    vocabulary = vectorizer.get("vocabulary")
    feature_contract = feature_contract or {}
    idf = np.asarray(vectorizer.get("idf"), dtype=np.float64)
    coefficient = np.asarray(head.get("coefficients"), dtype=np.float64)
    intercept = head.get("intercept")
    max_features = feature_contract.get("max_features")
    if (vectorizer.get("schema_version") != 1
            or vectorizer.get("analyzer") != "char" or vectorizer.get("ngram_range") != [3, 5]
            or isinstance(max_features, bool) or max_features != 100_000
            or (vectorizer.get("max_features") is not None and vectorizer.get("max_features") != max_features)
            or vectorizer.get("smooth_idf") is not True
            or vectorizer.get("lowercase") is not True or vectorizer.get("sublinear_tf") is not True
            or vectorizer.get("l2_normalized") is not True or not isinstance(vocabulary, dict)
            or not vocabulary or not isinstance(canonical_url, str) or not canonical_url
            or head.get("classes") != [0, 1]
            or feature_contract.get("analyzer") != "char"
            or feature_contract.get("ngram_range") != [3, 5]
            or feature_contract.get("lowercase") is not True
            or feature_contract.get("sublinear_tf") is not True):
        raise ValueError("url_contract_mismatch")
    size = len(vocabulary)
    indices = list(vocabulary.values())
    if (size > max_features
            or any(isinstance(index, bool) or not isinstance(index, int) for index in indices)
            or sorted(indices) != list(range(size)) or idf.shape != (size,) or coefficient.shape != (size,)
            or not np.isfinite(idf).all() or not np.isfinite(coefficient).all() or np.any(idf <= 0)
            or isinstance(intercept, bool) or not isinstance(intercept, (int, float)) or not math.isfinite(intercept)):
        raise ValueError("invalid_url_model")
    lowered = canonical_url.lower()
    counts = {}
    for width in range(3, 6):
        for offset in range(len(lowered) - width + 1):
            index = vocabulary.get(lowered[offset:offset + width])
            if index is not None:
                counts[index] = counts.get(index, 0) + 1
    values = {index: (1.0 + math.log(count)) * idf[index] for index, count in counts.items()}
    norm = math.sqrt(sum(value * value for value in values.values()))
    logit = float(intercept)
    if norm:
        logit += sum((value / norm) * coefficient[index] for index, value in values.items())
    if not math.isfinite(logit):
        raise ValueError("invalid_url_probability")
    return 1 / (1 + math.exp(-logit)) if logit >= 0 else math.exp(logit) / (1 + math.exp(logit))


def score_components(root: Path, hashes: dict, requirements: dict, raw_url: str | None,
                     image_path: Path | None, encoder_source_root: Path) -> dict:
    result = {}
    for kind, descriptor in requirements.items():
        try:
            if kind not in {"url", "visual"} or not isinstance(descriptor, dict):
                raise ValueError("unsupported_component")
            contract = verify_descriptor(root, hashes, descriptor)
            if kind == "url":
                probability = _url_score(root, descriptor, contract, raw_url)
            else:
                if contract.get("scoring_backend") != "json_linear_logistic":
                    raise ValueError("unsupported_visual_backend")
                artifact = json.loads(_contained(root, descriptor["artifact_file"]).read_text(encoding="utf-8"))
                probability = linear_probability(artifact, encode_image(image_path, contract, encoder_source_root))
            if not math.isfinite(probability) or not 0 <= probability <= 1:
                raise ValueError("invalid_probability")
            result[kind] = {"status": "observed", "phishing_probability": probability,
                            "model_version": descriptor["model_version"], "artifact_hashes": dict(descriptor)}
        except Exception as exc:
            # Celery soft limits must reach the task boundary to mark timeout.
            if type(exc).__name__ == "SoftTimeLimitExceeded":
                raise
            result[kind] = {"status": "unavailable", "phishing_probability": None,
                            "artifact_hashes": {}, "error_reason": "component_unavailable"}
    return result
