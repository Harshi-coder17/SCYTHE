# parser/authentication_parser.py

import re
import mailparser


class AuthenticationParser:

    @staticmethod
    def _extract(pattern: str, text: str):

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

        return None

    @staticmethod
    def parse(raw_email: bytes):

        mail = mailparser.parse_from_bytes(raw_email)

        auth_header = (
            mail.headers.get(
                "Authentication-Results",
                ""
            )
        )

        authentication = {

            "spf_result":
                AuthenticationParser._extract(
                    r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)",
                    auth_header
                ),

            "spf_domain":
                AuthenticationParser._extract(
                    r"smtp\.mailfrom=([^\s;]+)",
                    auth_header
                ),

            "dkim_result":
                AuthenticationParser._extract(
                    r"dkim=(pass|fail|none|temperror|permerror)",
                    auth_header
                ),

            "dkim_domain":
                AuthenticationParser._extract(
                    r"header\.d=([^\s;]+)",
                    auth_header
                ),

            "dkim_selector":
                AuthenticationParser._extract(
                    r"header\.s=([^\s;]+)",
                    auth_header
                ),

            "dmarc_result":
                AuthenticationParser._extract(
                    r"dmarc=(pass|fail|bestguesspass|none)",
                    auth_header
                ),

            "dmarc_policy":
                AuthenticationParser._extract(
                    r"policy\.p=([^\s;]+)",
                    auth_header
                ),

            "alignment_status": None,

            "authentication_result":
                auth_header if auth_header else None

        }

        ####################################################
        # SPF/DKIM alignment
        ####################################################

        if (
            authentication["spf_result"] == "pass"
            or
            authentication["dkim_result"] == "pass"
        ):
            authentication["alignment_status"] = True

        else:
            authentication["alignment_status"] = False

        return authentication