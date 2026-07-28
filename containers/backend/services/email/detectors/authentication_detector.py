"""
authentication_detector.py

Authentication Detector
-----------------------
Checks:
    - SPF
    - DKIM
    - DMARC
    - Domain Alignment

Input:
    Parsed email JSON from output.py

Output:
{
    "detector": "Authentication",
    "score": 55,
    "severity": "Medium",
    "reasons": [...]
}
"""


class AuthenticationDetector:

    def __init__(self):

        self.scoring = {

            "spf": {
                "pass": 0,
                "softfail": 10,
                "neutral": 5,
                "temperror": 10,
                "permerror": 15,
                "fail": 30,
                "none": 15
            },

            "dkim": {
                "pass": 0,
                "fail": 25,
                "none": 15
            },

            "dmarc": {
                "pass": 0,
                "quarantine": 10,
                "reject": 30,
                "fail": 30,
                "none": 15
            },

            "alignment": {
                "pass": 0,
                "fail": 20
            }

        }

    def detect(self, email_json):

        auth = email_json.get("authentication", {})

        score = 0
        reasons = []

        # ---------------- SPF ----------------

        spf = auth.get("spf_result", "none").lower()

        score += self.scoring["spf"].get(spf, 15)

        if spf != "pass":
            reasons.append(f"SPF: {spf}")

        # ---------------- DKIM ----------------

        dkim = auth.get("dkim_result", "none").lower()

        score += self.scoring["dkim"].get(dkim, 15)

        if dkim != "pass":
            reasons.append(f"DKIM: {dkim}")

        # ---------------- DMARC ----------------

        dmarc = auth.get("dmarc_result", "none").lower()

        score += self.scoring["dmarc"].get(dmarc, 15)

        if dmarc != "pass":
            reasons.append(f"DMARC: {dmarc}")

        # ---------------- Alignment ----------------

        alignment = auth.get("alignment_status", False)

        if not alignment:
            score += self.scoring["alignment"]["fail"]
            reasons.append("Domain alignment failed")

            score = min(score, 100)

        return {

            "detector": "Authentication",

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