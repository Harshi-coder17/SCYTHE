"""
Unit tests for Stage 2 intake (`services/stage2_analysis.py`), verifying
image validation, size limits, and ClamAV malware rejection.
"""

import pytest
from unittest.mock import patch, MagicMock

from services.stage2_analysis import run_stage2_analysis, _decode_and_validate_image
from schemas.stage2 import Stage2Request


def test_stage2_malware_rejection():
    import base64
    import io
    from PIL import Image
    buf = io.BytesIO()
    im = Image.new("RGBA", (10, 10), (255, 0, 0, 0))
    im.save(buf, format="PNG")
    valid_png_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    req = Stage2Request(
        url="http://example.com/phishing",
        screenshot_base64=valid_png_b64,
        html="<html><body>Malicious script</body></html>",
    )

    mock_user = MagicMock()
    mock_user.id = "user-uuid"

    mock_db = MagicMock()
    mock_scan = MagicMock()
    mock_scan.id = "12345678-1234-4234-a234-123456789abc"
    mock_db.add.side_effect = lambda obj: None
    mock_db.refresh.side_effect = lambda obj: setattr(obj, "id", "12345678-1234-4234-a234-123456789abc")

    # Mock ClamAV detecting malware on browser.html
    with patch("services.stage2_analysis.scan_file_clamav", side_effect=[(True, "Clean"), (False, "Win.Trojan.Phish FOUND")]):
        with pytest.raises(ValueError, match=r"Malware check rejected Stage 2 upload: Clean \| Win\.Trojan\.Phish FOUND"):
            run_stage2_analysis(req, mock_user, mock_db)


def test_image_intake_canonicalizes_tiff_to_png():
    import base64
    import io
    from PIL import Image

    source = io.BytesIO()
    Image.new("RGB", (13, 7), (12, 34, 56)).save(source, format="TIFF")

    normalized = _decode_and_validate_image(base64.b64encode(source.getvalue()).decode("ascii"))

    with Image.open(io.BytesIO(normalized)) as decoded:
        assert decoded.format == "PNG"
        assert decoded.size == (13, 7)
        assert decoded.getpixel((0, 0)) == (12, 34, 56)


def test_image_intake_discards_original_metadata():
    import base64
    import io
    from PIL import Image, PngImagePlugin

    source = io.BytesIO()
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("untrusted", "original container metadata")
    Image.new("RGB", (4, 4), "white").save(source, format="PNG", pnginfo=metadata)

    normalized = _decode_and_validate_image(base64.b64encode(source.getvalue()).decode("ascii"))

    with Image.open(io.BytesIO(normalized)) as decoded:
        assert decoded.format == "PNG"
        assert "untrusted" not in decoded.info
