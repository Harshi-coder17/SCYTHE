"""
ai_engine/ocr.py
=================
OCR text extraction from screenshot images using Tesseract / pytesseract.

Previously a placeholder that returned an empty string for every image.
Now implements real OCR via pytesseract so the consistency engine's
compare_ocr() method has actual text to compare between browser and
sandbox screenshots instead of two empty strings (which would always be
indeterminate and always skipped from the consistency score).

Requirements: pytesseract>=0.3.13, tesseract-ocr installed in the container.
The backend Dockerfile.worker installs tesseract-ocr via apt-get (`extract_text` executes inside `celery_worker`).
"""

import logging
import os
import re

from PIL import Image
Image.MAX_IMAGE_PIXELS = 25_000_000  # 5,000 x 5,000 px limit (~100MB max RGBA memory)

logger = logging.getLogger(__name__)

ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG", "GIF", "BMP", "WEBP"}
MAX_IMAGE_FILE_SIZE = 50 * 1024 * 1024  # 50MB


def extract_text(image_path: str) -> str:
    """
    Extract text from an image using Tesseract OCR.

    Returns the extracted text as a string. Returns an empty string on
    error (e.g., file not found, corrupt image, disallowed format) rather
    than raising — the consistency engine handles empty-string cases gracefully.
    """
    if not image_path:
        return ""

    _, ext = os.path.splitext(image_path.lower())
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        logger.warning("OCR: Disallowed or unsafe image extension %s for %s", ext, image_path)
        return ""

    try:
        if os.path.getsize(image_path) > MAX_IMAGE_FILE_SIZE:
            logger.warning("OCR: Image file exceeds 50MB limit: %s", image_path)
            return ""
    except OSError:
        logger.warning("OCR: Cannot access image file %s", image_path)
        return ""

    try:
        import pytesseract  # type: ignore[import-untyped]
    except ImportError:
        logger.error(
            "pytesseract is not installed — cannot extract text from %s. "
            "Add pytesseract to requirements.txt and rebuild the container.",
            image_path,
        )
        return ""

    try:
        with Image.open(image_path) as img:
            img_format = (img.format or "").upper()
            if img_format not in ALLOWED_IMAGE_FORMATS:
                logger.warning("OCR: Disallowed image format %s in %s", img_format, image_path)
                return ""
            text = pytesseract.image_to_string(img)

        if text:
            # H23: Sanitize OCR output to prevent downstream injection / XSS
            text = re.sub(r"<[^>]+>", "", text)
            text = text.replace("\x00", "")
            text = text[:10000]

        logger.debug(
            "OCR extracted %d chars from %s", len(text), image_path
        )
        return text
    except FileNotFoundError:
        logger.warning("OCR: image file not found: %s", image_path)
        return ""
    except Exception:
        logger.exception("OCR extraction failed for %s — returning empty string", image_path)
        return ""
