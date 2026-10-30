"""
ai_engine/vision.py
====================
Image analysis and brand impersonation detection via perceptual hashing.
"""

import json
import logging
import math
import os
import sys
from pathlib import Path

import imagehash
from PIL import Image, ImageStat

try:
    from config import settings
except ImportError:
    settings = None

# Prevent decompression bombs
Image.MAX_IMAGE_PIXELS = 25_000_000

logger = logging.getLogger(__name__)

DEFAULT_SIMILARITY_THRESHOLD = 0.90

class BrandMatcher:
    def __init__(self, reference_hashes: dict):
        self._reference = {}
        for brand, hex_str in reference_hashes.items():
            try:
                if not isinstance(hex_str, str) or not hex_str.strip():
                    continue
                self._reference[brand] = imagehash.hex_to_hash(hex_str)
            except Exception as e:
                logger.warning("Skipping malformed hash for brand %s: %s", brand, e)

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        if not path.exists():
            logger.info("No brand reference set at %s — brand-impersonation check skipped.", path)
            return cls({})
        try:
            with open(path) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                logger.warning("Brand reference set at %s is not a JSON dict", path)
                return cls({})
            return cls(data)
        except Exception as e:
            logger.warning("Failed to load brand reference set from %s: %s", path, e)
            return cls({})

    def match(self, screenshot_path, threshold=DEFAULT_SIMILARITY_THRESHOLD):
        if not self._reference or not screenshot_path:
            return None
        allowed_exts = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
        _, ext = os.path.splitext(str(screenshot_path).lower())
        if ext not in allowed_exts:
            logger.warning("BrandMatcher: Disallowed image extension %s for %s", ext, screenshot_path)
            return None
        try:
            if os.path.getsize(screenshot_path) > 50 * 1024 * 1024:
                logger.warning("BrandMatcher: Image file exceeds 50MB limit: %s", screenshot_path)
                return None
            with Image.open(screenshot_path) as img:
                img_fmt = (img.format or "").upper()
                if img_fmt not in {"PNG", "JPEG", "GIF", "BMP", "WEBP"}:
                    logger.warning("BrandMatcher: Disallowed image format %s for %s", img_fmt, screenshot_path)
                    return None
                target_hash = imagehash.phash(img)
        except Exception as e:
            logger.warning("Could not hash screenshot %s: %s", screenshot_path, e)
            return None

        best_brand, best_similarity = None, 0.0
        for brand, ref_hash in self._reference.items():
            try:
                distance = target_hash - ref_hash
                hash_bits = len(ref_hash)
                if not hash_bits or hash_bits <= 0:
                    continue
                similarity = 1.0 - (distance / hash_bits)
                similarity = max(0.0, min(1.0, float(similarity)))
                if similarity > best_similarity:
                    best_brand, best_similarity = brand, similarity
            except (TypeError, ValueError) as e:
                logger.warning("Skipping incompatible hash comparison for brand %s: %s", brand, e)
            except Exception as e:
                logger.warning("Unexpected error matching brand %s: %s", brand, e)

        if best_brand and best_similarity >= threshold:
            logger.debug("Brand match: %s at similarity %.3f", best_brand, best_similarity)
            return {"brand": best_brand, "similarity": round(best_similarity, 3)}
        return None

# Load references once at startup.
# Look first in adjacent ai_engine directory where reference_hashes.json is baked during Docker builds,
# falling back to ../../sandbox/backend/reference_hashes.json for local out-of-container dev runs.
_local_reference = os.path.join(os.path.dirname(__file__), "reference_hashes.json")
_fallback_reference = os.path.join(os.path.dirname(__file__), "../../sandbox/backend/reference_hashes.json")
_REFERENCE_PATH = os.environ.get(
    "BRAND_REFERENCE_JSON",
    _local_reference if os.path.exists(_local_reference) else _fallback_reference,
)
try:
    _matcher = BrandMatcher.from_file(_REFERENCE_PATH)
except Exception as e:
    logger.warning("Failed to initialize BrandMatcher from %s: %s", _REFERENCE_PATH, e)
    _matcher = BrandMatcher({})

def analyze_screenshot(image_path: str) -> dict:
    """
    Analyzes a screenshot for brand impersonation and extracts labels.
    Returns:
        {"logo": {"brand": str, "similarity": float} | None, "labels": list}
    """
    if not os.path.exists(image_path):
        logger.warning("analyze_screenshot called on missing file: %s", image_path)
        return {"logo": None, "labels": []}

    try:
        logo_match = _matcher.match(image_path)
    except Exception as e:
        logger.warning("Brand matching failed during analyze_screenshot(%s): %s", image_path, e)
        logo_match = None

    return {
        "logo": logo_match,
        "labels": []  # Extendable for object detection later
    }


def normalize_screenshot(image: Image.Image) -> Image.Image:
    """Standardize screenshot to 960x401 with top/center crop for MobileCLIP-S0."""
    rgb = image.convert("RGB")
    if rgb.width < 400 or rgb.height < 250:
        raise ValueError("incompatible_viewport")
    target_width, target_height = 960, 401
    target_ratio = target_width / target_height
    width, height = rgb.size
    if width / height < target_ratio:
        height = round(width / target_ratio)
        rgb = rgb.crop((0, 0, width, height))
    else:
        width = round(height * target_ratio)
        left = (rgb.width - width) // 2
        rgb = rgb.crop((left, 0, left + width, height))
    rgb = rgb.resize((target_width, target_height), Image.Resampling.LANCZOS)
    if ImageStat.Stat(rgb.convert("L")).stddev[0] < 2.0:
        raise ValueError("near_uniform_image")
    return rgb


_mobileclip_classifier = None
_mobileclip_encoder = None
_mobileclip_preprocess = None
_mobileclip_metadata = None


def _reset_mobileclip_cache():
    """Clear cached MobileCLIP encoder and classifier models (for testing/reloads)."""
    global _mobileclip_classifier, _mobileclip_encoder, _mobileclip_preprocess, _mobileclip_metadata
    _mobileclip_classifier = None
    _mobileclip_encoder = None
    _mobileclip_preprocess = None
    _mobileclip_metadata = None


def _resolve_mobileclip_paths():
    """Locate artifact directory, model checkpoint, vendor directory, and site-packages."""
    backend_dir = Path(__file__).resolve().parent.parent
    workspace_root = backend_dir.parent.parent.parent

    def configured_path(value):
        if not value:
            return None
        path = Path(value).expanduser()
        return path if path.is_absolute() else backend_dir / path

    # 1. Artifact directory candidates (containing classifier.joblib)
    artifact_candidates = []
    cfg_dir = getattr(settings, "MOBILECLIP_ARTIFACT_DIR", None) if settings else None
    if cfg_dir:
        artifact_candidates.append(configured_path(cfg_dir))
    artifact_candidates.extend([
        backend_dir / "models" / "mobileclip",
        workspace_root / "mobileclip-dataset" / "artifacts" / "mobileclip_v1",
    ])

    artifact_dir = None
    for cand in artifact_candidates:
        try:
            if cand and (cand / "classifier.joblib").is_file():
                artifact_dir = cand.resolve()
                break
        except Exception:
            continue

    # 2. Checkpoint candidates (mobileclip_s0.pt)
    checkpoint_candidates = []
    cfg_ckpt = getattr(settings, "MOBILECLIP_CHECKPOINT_PATH", None) if settings else None
    if cfg_ckpt:
        checkpoint_candidates.append(configured_path(cfg_ckpt))
    if artifact_dir:
        checkpoint_candidates.extend([
            artifact_dir / "mobileclip_s0.pt",
            artifact_dir / "checkpoints" / "mobileclip_s0.pt",
        ])
    checkpoint_candidates.extend([
        workspace_root / "mobileclip-dataset" / "checkpoints" / "mobileclip_s0.pt",
    ])

    checkpoint_path = None
    for cand in checkpoint_candidates:
        try:
            if cand and cand.is_file():
                checkpoint_path = cand.resolve()
                break
        except Exception:
            continue

    # 3. Vendor directory candidates (containing mobileclip package)
    vendor_candidates = []
    cfg_vendor = getattr(settings, "MOBILECLIP_VENDOR_DIR", None) if settings else None
    if cfg_vendor:
        vendor_candidates.append(configured_path(cfg_vendor))
    vendor_candidates.extend([
        workspace_root / "mobileclip-dataset" / "vendor" / "ml-mobileclip",
    ])

    vendor_dir = None
    for cand in vendor_candidates:
        try:
            if cand and (cand / "mobileclip" / "__init__.py").is_file():
                vendor_dir = cand.resolve()
                break
        except Exception:
            continue

    return artifact_dir, checkpoint_path, vendor_dir, None


def _get_or_load_mobileclip():
    """Load or return cached MobileCLIP visual classifier, encoder, and transforms."""
    global _mobileclip_classifier, _mobileclip_encoder, _mobileclip_preprocess, _mobileclip_metadata
    if _mobileclip_classifier is not None and _mobileclip_encoder is not None and _mobileclip_preprocess is not None:
        return _mobileclip_classifier, _mobileclip_encoder, _mobileclip_preprocess, _mobileclip_metadata

    if not settings or not getattr(settings, "MOBILECLIP_ENABLED", False):
        raise RuntimeError("mobileclip_disabled")

    artifact_dir, checkpoint_path, vendor_dir, _ = _resolve_mobileclip_paths()

    if not artifact_dir:
        raise FileNotFoundError("MobileCLIP artifact directory not found")
    classifier_path = artifact_dir / "classifier.joblib"
    if not classifier_path.is_file():
        raise FileNotFoundError(f"classifier.joblib not found in {artifact_dir}")

    if not checkpoint_path:
        raise FileNotFoundError("MobileCLIP checkpoint (mobileclip_s0.pt) not found")

    if not vendor_dir:
        raise FileNotFoundError("ml-mobileclip vendor directory not found")

    import joblib
    import torch

    classifier = joblib.load(str(classifier_path))

    if vendor_dir and str(vendor_dir) not in sys.path:
        sys.path.insert(0, str(vendor_dir))

    import mobileclip

    torch.set_num_threads(min(8, os.cpu_count() or 1))
    encoder, _, preprocess = mobileclip.create_model_and_transforms(
        "mobileclip_s0", pretrained=str(checkpoint_path), reparameterize=True, device="cpu"
    )
    encoder.eval()
    for param in encoder.parameters():
        param.requires_grad_(False)

    threshold = 0.433438
    thresh_file = artifact_dir / "threshold.json"
    if thresh_file.is_file():
        try:
            threshold = float(json.loads(thresh_file.read_text(encoding="utf-8")).get("threshold", threshold))
        except Exception:
            pass

    contract_version = "mobileclip_v1"
    contract_file = artifact_dir / "feature_contract.json"
    if contract_file.is_file():
        try:
            contract_version = json.loads(contract_file.read_text(encoding="utf-8")).get("version", contract_version)
        except Exception:
            pass

    meta = {
        "model_version": contract_version,
        "threshold": threshold,
        "artifact_dir": str(artifact_dir),
        "checkpoint_path": str(checkpoint_path),
    }

    _mobileclip_classifier = classifier
    _mobileclip_encoder = encoder
    _mobileclip_preprocess = preprocess
    _mobileclip_metadata = meta

    return _mobileclip_classifier, _mobileclip_encoder, _mobileclip_preprocess, _mobileclip_metadata


def score_screenshot_mobileclip(image_path: str | Path | None) -> dict:
    """
    Evaluates screenshot using MobileCLIP visual classifier.

    Returns float phishing probability in [0.0, 1.0] and metadata.
    If image is missing, unreadable, or dependencies/model are unavailable,
    gracefully fallbacks to {"score": None, "status": "UNAVAILABLE"} with logging.
    """
    if not image_path:
        logger.warning("score_screenshot_mobileclip called with empty image_path")
        return {"score": None, "status": "UNAVAILABLE", "visual_phishing_probability": None, "reason": "missing_image"}

    path = Path(image_path)
    if not path.is_file():
        logger.warning("score_screenshot_mobileclip called on missing file: %s", image_path)
        return {"score": None, "status": "UNAVAILABLE", "visual_phishing_probability": None, "reason": "missing_image"}

    try:
        from PIL import Image
        with Image.open(path) as image:
            standardized = normalize_screenshot(image)
    except Exception as exc:
        logger.warning("score_screenshot_mobileclip: image unreadable or invalid (%s): %s", image_path, exc)
        return {"score": None, "status": "UNAVAILABLE", "visual_phishing_probability": None, "reason": str(exc)}

    try:
        classifier, encoder, preprocess, meta = _get_or_load_mobileclip()
    except Exception as exc:
        logger.warning("score_screenshot_mobileclip: dependencies or model unavailable: %s", exc)
        return {"score": None, "status": "UNAVAILABLE", "visual_phishing_probability": None, "reason": str(exc)}

    try:
        import torch
        import torch.nn.functional as functional

        tensor = preprocess(standardized).unsqueeze(0).to(dtype=torch.float32)
        with torch.inference_mode():
            embedding = functional.normalize(encoder.encode_image(tensor).float(), dim=-1).cpu().numpy()

        if hasattr(classifier, "predict_proba"):
            probs = classifier.predict_proba(embedding)
            if hasattr(classifier, "classes_") and 1 in list(classifier.classes_):
                pos_idx = list(classifier.classes_).index(1)
                prob = float(probs[0][pos_idx])
            elif len(probs[0]) > 1:
                prob = float(probs[0][1])
            else:
                prob = float(probs[0][0])
        elif hasattr(classifier, "predict"):
            res = classifier.predict(embedding)
            prob = float(res[0]) if hasattr(res, "__len__") else float(res)
        else:
            res = classifier(embedding)
            prob = float(res[0]) if hasattr(res, "__len__") else float(res)

        if not math.isfinite(prob):
            raise ValueError(f"Inference produced non-finite probability: {prob}")

        prob = max(0.0, min(1.0, float(prob)))
        threshold = meta.get("threshold", 0.433438) if meta else 0.433438
        model_version = meta.get("model_version", "mobileclip_v1") if meta else "mobileclip_v1"
        is_phishing = int(prob >= threshold) if threshold is not None else 0

        metadata = {
            "model_version": model_version,
            "threshold": threshold,
            "experimental_threshold": threshold,
            "experimental_class": is_phishing,
            "automatic_incident_signal": False,
            "status": "OBSERVED",
        }

        return {
            "score": prob,
            "status": "OBSERVED",
            "visual_phishing_probability": prob,
            "metadata": metadata,
            "model_version": model_version,
            "threshold": threshold,
            "classification": is_phishing,
        }
    except Exception as exc:
        logger.warning("score_screenshot_mobileclip: inference failed on %s: %s", image_path, exc)
        return {"score": None, "status": "UNAVAILABLE", "visual_phishing_probability": None, "reason": str(exc)}
