"""
content_detector.py

Content Detector
----------------
Checks:
    - Credential Theft Language
    - Financial Scam Language
    - Urgency
    - Spam Score
    - HTML Obfuscation
    - Hidden Text
    - Login Form
    - JavaScript
    - External Resources
    - Suspicious Keywords

Input:
    Parsed JSON from output.py

Output:
{
    "detector": "Content",
    "score": 75,
    "severity": "High",
    "reasons": [...]
}
"""


class ContentDetector:

    def __init__(self):

        self.weights = {

            "credential_theft": 35,

            "financial_scam": 25,

            "urgency": 20,

            "spam": 20,

            "html_obfuscation": 15,

            "hidden_text": 20,

            "login_form": 30,

            "javascript": 25,

            "external_resources": 10,

            "suspicious_keywords": 15

        }

    def detect(self, email_json):

        content = email_json.get("content", {})

        score = 0
        reasons = []

        # -----------------------------
        # Credential Theft Score
        # -----------------------------

        credential_score = content.get("credential_score", 0)

        if credential_score >= 80:
            score += self.weights["credential_theft"]
            reasons.append(
                f"High credential theft score ({credential_score})"
            )

        # -----------------------------
        # Financial Scam
        # -----------------------------

        financial_score = content.get("financial_score", 0)

        if financial_score >= 80:
            score += self.weights["financial_scam"]
            reasons.append(
                f"Financial scam indicators ({financial_score})"
            )

        # -----------------------------
        # Urgency
        # -----------------------------

        urgency_score = content.get("urgency_score", 0)

        if urgency_score >= 80:
            score += self.weights["urgency"]
            reasons.append(
                f"Urgent language detected ({urgency_score})"
            )

        # -----------------------------
        # Spam Score
        # -----------------------------

        spam_score = content.get("spam_score", 0)

        if spam_score >= 80:
            score += self.weights["spam"]
            reasons.append(
                f"High spam score ({spam_score})"
            )

        # -----------------------------
        # HTML Obfuscation
        # -----------------------------

        if content.get("html_obfuscation", False):

            score += self.weights["html_obfuscation"]

            reasons.append("HTML obfuscation detected")

        # -----------------------------
        # Hidden Text
        # -----------------------------

        if content.get("hidden_text", False):

            score += self.weights["hidden_text"]

            reasons.append("Hidden text detected")

        # -----------------------------
        # Login Form
        # -----------------------------

        if content.get("login_form", False):

            score += self.weights["login_form"]

            reasons.append("Embedded login form detected")

        # -----------------------------
        # JavaScript
        # -----------------------------

        if content.get("javascript_present", False):

            score += self.weights["javascript"]

            reasons.append("JavaScript present")

        # -----------------------------
        # External Resources
        # -----------------------------

        if content.get("external_resources", False):

            score += self.weights["external_resources"]

            reasons.append("External resources loaded")

        # -----------------------------
        # Suspicious Keywords
        # -----------------------------

        keyword_count = content.get("suspicious_keyword_count", 0)

        if keyword_count >= 5:

            score += self.weights["suspicious_keywords"]

            reasons.append(
                f"{keyword_count} suspicious keywords found"
            )

        score = min(score, 100)

        return {

            "detector": "Content",

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