# parser/metadata_parser.py

import mailparser


class MetadataParser:

    @staticmethod
    def parse(raw_email: bytes):

        mail = mailparser.parse_from_bytes(raw_email)

        to_address = [
            {
                "display_name": x[0],
                "email": x[1]  
            }
            for x in mail.to
        ]

        cc_address = [
            {
                "display_name": x[0],
                "email": x[1]
            }
            for x in mail.cc
        ] if mail.cc else None

        bcc_address = [
            {
                "display_name": x[0],
                "email": x[1]
            }
            for x in mail.bcc
        ] if mail.bcc else None

        reply_to = [
            {
                "display_name": x[0],
                "email": x[1]
            }
            for x in mail.reply_to
        ] if mail.reply_to else None

        recipient_count = (
            len(mail.to)
            + len(mail.cc)
            + len(mail.bcc)
        )

        return {

            "from_address": (
                mail.from_[0][1]
                if mail.from_
                else None
            ),

            "display_name": (
                mail.from_[0][0]
                if mail.from_
                else None
            ),

            "to_address": to_address,

            "cc_address": cc_address,

            "bcc_address": bcc_address,

            "reply_to": reply_to,

            "return_path": (
                mail.headers.get("Return-Path")
            ),

            "subject": mail.subject,

            "date": (
                mail.date.isoformat()
                if mail.date
                else None
            ),

            "message_id": mail.message_id,

            "thread_id": (
                mail.headers.get("Thread-Index")
                or
                mail.headers.get("Thread-ID")
            ),

            "recipient_count": recipient_count
        }