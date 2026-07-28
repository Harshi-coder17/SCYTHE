"""
identity_detector.py

Identity Detector
-----------------
Checks:
    - Reply-To mismatch
    - Return-Path mismatch
    - Message-ID mismatch
    - Display Name spoofing
    - Typosquatting
    - Homoglyph / Punycode

Input:
    Parsed email JSON from output.py

Output:
{
    "detector": "Identity",
    "score": 65,
    "severity": "High",
    "reasons": [...]
}
"""


class IdentityDetector:

    def __init__(self):

        self.weights = {

            "reply_to_mismatch": 25,

            "return_path_mismatch": 15,

            "message_id_mismatch": 15,

            "display_name_spoof": 20,

            "typosquatting": 30,

            "homoglyph": 30

        }

    def detect(self, email_json):

        metadata = email_json.get("metadata", {})
        authentication = email_json.get("authentication", {})

        score = 0
        reasons = []

        from_domain = metadata.get("from_domain", "").lower()
        reply_domain = metadata.get("reply_to_domain", "").lower()
        return_domain = metadata.get("return_path_domain", "").lower()
        message_domain = metadata.get("message_id_domain", "").lower()

        alignment = authentication.get("alignment_status", "fail")

        display_spoof = metadata.get("display_name_spoof", False)
        typosquatting = metadata.get("typosquatting", False)
        homoglyph = metadata.get("homoglyph_detected", False)

        # ---------------------------------
        # Reply-To mismatch
        # ---------------------------------

        if (
            reply_domain and
            from_domain and
            reply_domain != from_domain
        ):

            score += self.weights["reply_to_mismatch"]

            reasons.append(
                f"Reply-To domain differs ({reply_domain})"
            )

        # ---------------------------------
        # Return-Path mismatch
        # ---------------------------------

        if (
            return_domain and
            from_domain and
            return_domain != from_domain and
            not alignment 
        ):

            score += self.weights["return_path_mismatch"]

            reasons.append(
                f"Return-Path differs ({return_domain})"
            )

        # ---------------------------------
        # Message-ID mismatch
        # ---------------------------------

        if (
            message_domain and
            from_domain and
            message_domain != from_domain
        ):

            score += self.weights["message_id_mismatch"]

            reasons.append(
                f"Message-ID domain differs ({message_domain})"
            )

        # ---------------------------------
        # Display Name Spoof
        # ---------------------------------

        if display_spoof:

            score += self.weights["display_name_spoof"]

            reasons.append(
                "Display Name spoof detected"
            )

        # ---------------------------------
        # Typosquatting
        # ---------------------------------

        if typosquatting:

            score += self.weights["typosquatting"]

            reasons.append(
                "Typosquatting detected"
            )

        # ---------------------------------
        # Homoglyph / Punycode
        # ---------------------------------

        if homoglyph:

            score += self.weights["homoglyph"]

            reasons.append(
                "Homoglyph domain detected"
            )

        score = min(score, 100)

        return {

            "detector": "Identity",

            "score": score,

            "severity": self.get_severity(score),

            "reasons": reasons

        }

    @staticmethod
    def get_severity(score):

        if score <= 20:
            return "Safe"

        elif score <= 40:
            return "Low"

        elif score <= 60:
            return "Medium"

        elif score <= 80:
            return "High"

        return "Critical"