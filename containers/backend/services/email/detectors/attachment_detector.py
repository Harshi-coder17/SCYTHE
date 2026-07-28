"""
attachment_detector.py

Attachment Detector
-------------------
Checks:
    - Malware Detection
    - Office Macros
    - Password Protected Archives
    - Dangerous File Extensions
    - Double Extensions
    - Executable Files
    - Suspicious MIME Types
    - Large Attachment Count

Input:
    Parsed JSON from output.py

Output:
{
    "detector": "Attachment",
    "score": 65,
    "severity": "High",
    "reasons": [...]
}
"""


class AttachmentDetector:

    def __init__(self):

        self.weights = {

            "malware": 60,

            "macro": 30,

            "password_protected": 20,

            "dangerous_extension": 40,

            "double_extension": 30,

            "executable": 40,

            "suspicious_mime": 20,

            "many_attachments": 10

        }

    def detect(self, email_json):

        attachments = email_json.get("attachments", {})

        score = 0
        reasons = []

        # ---------------------------------
        # Attachment Count
        # ---------------------------------

        count = attachments.get("attachment_count", 0)

        if count > 5:
            score += self.weights["many_attachments"]
            reasons.append(f"Large number of attachments ({count})")

        # ---------------------------------
        # Malware Detection
        # ---------------------------------

        if attachments.get("malware_detected", False):
            score += self.weights["malware"]
            reasons.append("Malware detected")

        # ---------------------------------
        # Office Macro
        # ---------------------------------

        if attachments.get("macro_present", False):
            score += self.weights["macro"]
            reasons.append("Office macro detected")

        # ---------------------------------
        # Password Protected Archive
        # ---------------------------------

        if attachments.get("password_protected", False):
            score += self.weights["password_protected"]
            reasons.append("Password-protected attachment")

        # ---------------------------------
        # Dangerous Extension
        # ---------------------------------

        if attachments.get("dangerous_extension", False):
            score += self.weights["dangerous_extension"]
            reasons.append("Dangerous attachment extension")

        # ---------------------------------
        # Double Extension
        # ---------------------------------

        if attachments.get("double_extension", False):
            score += self.weights["double_extension"]
            reasons.append("Double extension detected")

        # ---------------------------------
        # Executable
        # ---------------------------------

        if attachments.get("executable", False):
            score += self.weights["executable"]
            reasons.append("Executable attachment")

        # ---------------------------------
        # Suspicious MIME Type
        # ---------------------------------

        if attachments.get("suspicious_mime", False):
            score += self.weights["suspicious_mime"]
            reasons.append("Suspicious MIME type")

        score = min(score, 100)

        return {

            "detector": "Attachment",

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