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


class AttachmentParser:

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
            if not filename and disposition != "attachment":
                continue
            count += 1
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes) or len(payload) > 25 * 1024 * 1024:
                errors.append("Attachment unavailable or exceeds the 25 MB inspection limit")
                continue
            filename = filename or "attachment"
            suffix = os.path.splitext(filename)[1][:20]
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
                    handle.write(payload)
                    temporary = handle.name
                results.append({
                    "attachment_name": filename, "attachment_size": len(payload),
                    "file_extension": AttachmentParser.extension(filename),
                    "mime_type": part.get_content_type(), "sha256_hash": AttachmentParser.sha256(payload),
                    "malware_detected": None, "macro_present": AttachmentParser.has_macro(temporary),
                    "content_disposition": disposition or "attachment",
                    "is_inline": disposition == "inline",
                    "attachment_password_protected": AttachmentParser.is_password_protected(temporary),
                })
            finally:
                if temporary is not None:
                    os.unlink(temporary)
        return {"attachment_count": count, "attachments": results, "analysis_errors": errors}
