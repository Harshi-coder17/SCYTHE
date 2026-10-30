# parser/metadata_parser.py

try:
    import mailparser
except ImportError:
    mailparser = None


class MetadataParser:

    @staticmethod
    def parse(raw_email: bytes):
        if mailparser is None:
            import email as email_lib
            from email.utils import getaddresses, parsedate_to_datetime
            msg = email_lib.message_from_bytes(raw_email)
            to_raw = getaddresses(msg.get_all("to", []))
            to_address = [{"display_name": x[0], "email": x[1]} for x in to_raw]
            cc_raw = getaddresses(msg.get_all("cc", []))
            cc_address = [{"display_name": x[0], "email": x[1]} for x in cc_raw] if cc_raw else None
            bcc_raw = getaddresses(msg.get_all("bcc", []))
            bcc_address = [{"display_name": x[0], "email": x[1]} for x in bcc_raw] if bcc_raw else None
            reply_raw = getaddresses(msg.get_all("reply-to", []))
            reply_to = [{"display_name": x[0], "email": x[1]} for x in reply_raw] if reply_raw else None
            from_raw = getaddresses(msg.get_all("from", []))
            date_hdr = msg.get("date")
            date_iso = None
            if date_hdr:
                try:
                    date_iso = parsedate_to_datetime(date_hdr).isoformat()
                except Exception:
                    pass
            recipient_count = len(to_address) + (len(cc_address) if cc_address else 0) + (len(bcc_address) if bcc_address else 0)
            return {
                "from_address": from_raw[0][1] if from_raw else None,
                "display_name": from_raw[0][0] if from_raw else None,
                "to_address": to_address,
                "cc_address": cc_address,
                "bcc_address": bcc_address,
                "reply_to": reply_to,
                "return_path": msg.get("Return-Path"),
                "subject": msg.get("Subject"),
                "date": date_iso,
                "message_id": msg.get("Message-ID"),
                "thread_id": msg.get("Thread-Index") or msg.get("Thread-ID"),
                "recipient_count": recipient_count
            }

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