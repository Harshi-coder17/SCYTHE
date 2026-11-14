# parser/attachment_parser.py

import hashlib
import os
import tempfile
import zipfile
import email

try:
    import py7zr
except ImportError:
    py7zr = None

try:
    import rarfile
except ImportError:
    rarfile = None

try:
    from oletools.olevba import VBA_Parser
except ImportError:
    VBA_Parser = None

try:
    import cv2
    import numpy as np
    _HAS_CV2 = True
except ImportError:
    _HAS_CV2 = False

try:
    from pyzbar import pyzbar
    _HAS_PYZBAR = True
except (ImportError, OSError):
    _HAS_PYZBAR = False


class AttachmentParser:

    IMAGE_EXTENSIONS = frozenset({
        ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif", ".gif"
    })

    @staticmethod
    def sha256(data):

        if isinstance(data, str):
            data = data.encode()

        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def extension(filename):

        if not filename:
            return None

        return os.path.splitext(filename)[1].lower()

    @staticmethod
    def is_inline(disposition):

        if not disposition:
            return False

        return disposition.lower() == "inline"

    #######################################################
    # QR Code Extraction (Quishing Defense)
    #######################################################

    @staticmethod
    def extract_qr_codes(image_bytes: bytes) -> list[str]:
        """
        Extract and decode QR codes from raw image bytes.
        Uses pyzbar (if installed) with OpenCV QRCodeDetector / QRCodeDetectorMulti fallback.
        """
        if not image_bytes:
            return []

        results: list[str] = []
        seen = set()

        def _add(text: str):
            if text and text.strip():
                clean = text.strip()
                if clean not in seen:
                    seen.add(clean)
                    results.append(clean)

        # 1. Try pyzbar if available
        if _HAS_PYZBAR:
            try:
                from PIL import Image
                import io
                img_pil = Image.open(io.BytesIO(image_bytes))
                decoded = pyzbar.decode(img_pil)
                for item in decoded:
                    if item.data:
                        _add(item.data.decode("utf-8", errors="ignore"))
            except Exception:
                pass

        # 2. Try OpenCV (multi + single detector)
        if _HAS_CV2:
            try:
                np_arr = np.frombuffer(image_bytes, np.uint8)
                img = cv2.imdecode(np_arr, cv2.IMREAD_GRAYSCALE)
                if img is not None:
                    detector = cv2.QRCodeDetector()
                    if hasattr(detector, "detectAndDecodeMulti"):
                        try:
                            ok, decoded_info, _, _ = detector.detectAndDecodeMulti(img)
                            if ok and decoded_info:
                                for s in decoded_info:
                                    _add(s)
                        except Exception:
                            pass
                    if not results:
                        try:
                            single_data, _, _ = detector.detectAndDecode(img)
                            _add(single_data)
                        except Exception:
                            pass
            except Exception:
                pass

        return results

    #######################################################
    # Office Macro Detection
    #######################################################

    @staticmethod
    def has_macro(path):

        if VBA_Parser is None:
            return False

        try:

            parser = VBA_Parser(path)
            try:
                return parser.detect_vba_macros()
            finally:
                parser.close()

        except Exception:

            return False

    #######################################################
    # Password Protected Archives
    #######################################################

    @staticmethod
    def is_password_protected(path):

        ext = os.path.splitext(path)[1].lower()

        try:

            if ext == ".zip":

                with zipfile.ZipFile(path) as z:

                    for info in z.infolist():

                        if info.flag_bits & 0x1:
                            return True

                return False

            elif ext == ".7z":

                if py7zr is None:
                    return True
                with py7zr.SevenZipFile(path):

                    return False

            elif ext == ".rar":

                if rarfile is None:
                    return True
                with rarfile.RarFile(path) as r:

                    return r.needs_password()

        except Exception:

            return True

        return False

    #######################################################
    # Malware Placeholder
    #######################################################

    @staticmethod
    def malware_detected(path):

        """
        Replace later with

        - VirusTotal
        - ClamAV
        - YARA

        """

        return None

    #######################################################

    @staticmethod
    def parse(raw_email):
        """Inspect decoded MIME bytes and always remove private temporary files."""
        message = email.message_from_bytes(raw_email)
        results = []
        errors = []
        count = 0
        for part in message.walk():
            filename = part.get_filename()
            disposition = part.get_content_disposition()
            mime_type = (part.get_content_type() or "").lower()
            if not filename and disposition != "attachment" and not mime_type.startswith("image/"):
                continue
            count += 1
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes) or len(payload) > 25 * 1024 * 1024:
                errors.append("Attachment unavailable or exceeds the 25 MB inspection limit")
                continue
            filename = filename or "attachment"
            ext = AttachmentParser.extension(filename)
            suffix = ext[:20] if ext else ".bin"
            temporary = None
            qr_codes = []
            is_image = mime_type.startswith("image/") or (ext in AttachmentParser.IMAGE_EXTENSIONS)
            if is_image:
                try:
                    qr_codes = AttachmentParser.extract_qr_codes(payload)
                except Exception:
                    qr_codes = []

            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
                    handle.write(payload)
                    temporary = handle.name
                results.append({
                    "attachment_name": filename,
                    "attachment_size": len(payload),
                    "file_extension": ext,
                    "mime_type": mime_type,
                    "sha256_hash": AttachmentParser.sha256(payload),
                    "malware_detected": None,
                    "macro_present": AttachmentParser.has_macro(temporary),
                    "content_disposition": disposition or ("inline" if mime_type.startswith("image/") else "attachment"),
                    "is_inline": disposition == "inline" or (not disposition and mime_type.startswith("image/")),
                    "attachment_password_protected": AttachmentParser.is_password_protected(temporary),
                    "qr_codes": qr_codes,
                    "has_qr_code": bool(qr_codes),
                })
            finally:
                if temporary is not None:
                    os.unlink(temporary)
        return {"attachment_count": count, "attachments": results, "analysis_errors": errors}
