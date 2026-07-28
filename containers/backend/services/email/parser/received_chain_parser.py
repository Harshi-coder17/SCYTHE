import re
import mailparser


class ReceivedChainParser:

    IPV4_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

    @staticmethod
    def extract(pattern, text):

        match = re.search(
            pattern,
            text,
            re.IGNORECASE | re.DOTALL
        )

        if match:
            return match.group(1).strip()

        return None

    @staticmethod
    def parse(raw_email: bytes):

        mail = mailparser.parse_from_bytes(raw_email)

        received_headers = mail.headers.get("Received", [])

        if isinstance(received_headers, str):
                received_headers = [received_headers]
        originating_ip = None

        received_from = []
        received_by = []
        received_with = []
        received_id = []
        received_for = []
        received_timestamp = []

        ###################################################
        # Parse each Received header
        ###################################################

        for header in received_headers:

            ###################################################
            # from
            ###################################################

            received_from.append(

                ReceivedChainParser.extract(

                    r"from\s+(.*?)(?=\s+by\s)",

                    header

                )

            )

            ###################################################
            # by
            ###################################################

            received_by.append(

                ReceivedChainParser.extract(

                    r"by\s+(.*?)(?=\s+with\s|\s+id\s|\s+for\s|;)",

                    header

                )

            )

            ###################################################
            # with
            ###################################################

            received_with.append(

                ReceivedChainParser.extract(

                    r"with\s+([^\s;]+)",

                    header

                )

            )

            ###################################################
            # id
            ###################################################

            received_id.append(

                ReceivedChainParser.extract(

                    r"id\s+([^\s;]+)",

                    header

                )

            )

            ###################################################
            # for
            ###################################################

            received_for.append(

                ReceivedChainParser.extract(

                    r"for\s+<?([^>;]+)",

                    header

                )

            )

            ###################################################
            # timestamp
            ###################################################

            if ";" in header:

                received_timestamp.append(

                    header.split(";")[-1].strip()

                )

            else:

                received_timestamp.append(None)

        ###################################################
        # Originating IP
        ###################################################

        for header in reversed(received_headers):

            ips = ReceivedChainParser.IPV4_PATTERN.findall(
                header
            )

            if ips:

                originating_ip = ips[0]

                break

        ###################################################
        # Sending host
        ###################################################

        sender_hostname = None

        if received_from:

            sender_hostname = received_from[-1]

        ###################################################

        return {

            "received_count":
                len(received_headers),

            "originating_ip":
                originating_ip,

            "sender_hostname":
                sender_hostname,

            ###################################################
            # Filled by enrichment module later
            ###################################################

            "sender_country":
                None,

            "sender_asn":
                None,

            "reverse_dns":
                None,

            ###################################################

            "received_headers":
                received_headers,

            "received_from":
                received_from,

            "received_by":
                received_by,

            "received_with":
                received_with,

            "received_id":
                received_id,

            "received_for":
                received_for,

            "received_timestamp":
                received_timestamp

        }