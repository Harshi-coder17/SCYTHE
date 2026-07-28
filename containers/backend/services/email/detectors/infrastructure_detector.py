"""
infrastructure_detector.py

Infrastructure Detector
-----------------------
Checks:
    - Sender IP Reputation
    - ASN Reputation
    - Reverse DNS
    - Country Mismatch
    - Hop Count
    - DNSSEC

Input:
    Parsed JSON from output.py

Output:
{
    "detector": "Infrastructure",
    "score": 45,
    "severity": "Medium",
    "reasons": [...]
}
"""


class InfrastructureDetector:

    def __init__(self):

        self.weights = {

            "blacklisted_ip": 40,

            "poor_asn": 25,

            "missing_reverse_dns": 15,

            "country_mismatch": 20,

            "high_hop_count": 10,

            "dnssec_missing": 10

        }

    def detect(self, email_json):

        routing = email_json.get("routing", {})
        domain = email_json.get("domain", {})

        score = 0
        reasons = []

        # -----------------------------
        # Sender IP Reputation
        # -----------------------------

        ip_blacklisted = routing.get("ip_blacklisted", False)

        if ip_blacklisted:
            score += self.weights["blacklisted_ip"]
            reasons.append("Originating IP is blacklisted")

        # -----------------------------
        # ASN Reputation
        # -----------------------------

        asn_reputation = routing.get("asn_reputation", "good").lower()

        if asn_reputation == "poor":
            score += self.weights["poor_asn"]
            reasons.append("Poor ASN reputation")

        # -----------------------------
        # Reverse DNS
        # -----------------------------

        reverse_dns = routing.get("reverse_dns_exists", True)

        if not reverse_dns:
            score += self.weights["missing_reverse_dns"]
            reasons.append("Reverse DNS record missing")

        # -----------------------------
        # Country Mismatch
        # -----------------------------

        country_match = routing.get("country_matches_sender", True)

        if not country_match:
            score += self.weights["country_mismatch"]
            reasons.append("Origin country differs from expected sender")

        # -----------------------------
        # Hop Count
        # -----------------------------

        hop_count = routing.get("hop_count", 0)

        if hop_count > 15:
            score += self.weights["high_hop_count"]
            reasons.append(f"High hop count ({hop_count})")

        # -----------------------------
        # DNSSEC
        # -----------------------------

        dnssec = domain.get("dnssec_enabled", True)

        if not dnssec:
            score += self.weights["dnssec_missing"]
            reasons.append("DNSSEC not enabled")

        score = min(score, 100)

        return {

            "detector": "Infrastructure",

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