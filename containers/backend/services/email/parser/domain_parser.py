import re
import dns.resolver
import dns.flags
import dns.message
import dns.query
import mailparser


class DomainParser:

    @staticmethod
    def extract_domain(value):

        if not value:
            return None

        match = re.search(r'@([A-Za-z0-9.-]+)', value)

        if match:
            return match.group(1).lower()

        return None

    @staticmethod
    def get_mx_records(domain):

        if not domain:
            return None

        try:

            answers = dns.resolver.resolve(domain, "MX")

            mx = []

            for record in answers:
                mx.append(str(record.exchange).rstrip("."))

            return mx

        except Exception:

            return None

    @staticmethod
    def check_dnssec(domain):

        if not domain:
            return None

        try:

            query = dns.message.make_query(
                domain,
                dns.rdatatype.DNSKEY,
                want_dnssec=True
            )

            response = dns.query.udp(
                query,
                "8.8.8.8",
                timeout=5
            )

            return bool(
                response.flags & dns.flags.AD
            )

        except Exception:

            return None

    @staticmethod
    def parse(raw_email: bytes):

        mail = mailparser.parse_from_bytes(raw_email)

        ###################################################
        # Sender Domain
        ###################################################

        sender_domain = None

        if mail.from_:

            sender_domain = DomainParser.extract_domain(
                mail.from_[0][1]
            )

        ###################################################
        # Reply-To Domain
        ###################################################

        reply_to_domain = None

        if mail.reply_to:

            reply_to_domain = DomainParser.extract_domain(
                mail.reply_to[0][1]
            )

        ###################################################
        # Return-Path Domain
        ###################################################

        return_path_domain = DomainParser.extract_domain(
            mail.headers.get("Return-Path")
        )

        ###################################################
        # Message-ID Domain
        ###################################################

        message_id_domain = None

        if mail.message_id:

            match = re.search(
                r'@([^>]+)',
                mail.message_id
            )

            if match:
                message_id_domain = match.group(1).lower()

        ###################################################
        # DKIM Domain
        ###################################################

        authentication = mail.headers.get(
            "Authentication-Results",
            ""
        )

        match = re.search(
            r"header\.d=([^\s;]+)",
            authentication,
            re.IGNORECASE
        )

        dkim_domain = (
            match.group(1).lower()
            if match
            else None
        )

        ###################################################
        # DNS Lookups
        ###################################################

        mx_records = DomainParser.get_mx_records(
            sender_domain
        )

        dnssec_enabled = DomainParser.check_dnssec(
            sender_domain
        )

        ###################################################

        return {

            "sender_domain": sender_domain,

            "mx_records": mx_records,

            "dnssec_enabled": dnssec_enabled,

            "reply_to_domain": reply_to_domain,

            "return_path_domain": return_path_domain,

            "message_id_domain": message_id_domain,

            "dkim_domain": dkim_domain

        }