# parser/attachment_parser.py

import hashlib
import os
import tempfile
import zipfile
import py7zr
import rarfile
import mailparser

from oletools.olevba import VBA_Parser


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

        try:

            parser = VBA_Parser(path)

            return parser.detect_vba_macros()

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

                with py7zr.SevenZipFile(path):

                    return False

            elif ext == ".rar":

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

        mail = mailparser.parse_from_bytes(raw_email)

        results = []

        for attachment in mail.attachments:

            payload = attachment.get("payload")

            if isinstance(payload, str):
                payload = payload.encode()

            filename = attachment.get("filename")

            disposition = (
                attachment.get(
                    "content-disposition"
                )
                or
                "attachment"
            )

            ##################################################
            # Save temporary file
            ##################################################

            suffix = ""

            if filename:
                suffix = os.path.splitext(filename)[1]

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=suffix
            ) as tmp:

                tmp.write(payload)

                temp_path = tmp.name

            ##################################################

            results.append({

                "attachment_name":
                    filename,

                "attachment_size":
                    len(payload),

                "file_extension":
                    AttachmentParser.extension(
                        filename
                    ),

                "mime_type":
                    attachment.get(
                        "mail_content_type"
                    ),

                "sha256_hash":
                    AttachmentParser.sha256(
                        payload
                    ),

                "malware_detected":
                    AttachmentParser.malware_detected(
                        temp_path
                    ),

                "macro_present":
                    AttachmentParser.has_macro(
                        temp_path
                    ),

                "content_disposition":
                    disposition,

                "is_inline":
                    AttachmentParser.is_inline(
                        disposition
                    ),

                "attachment_password_protected":
                    AttachmentParser.is_password_protected(
                        temp_path
                    )
            })

        return {

            "attachment_count":
                len(results),

            "attachments":
                results

        }