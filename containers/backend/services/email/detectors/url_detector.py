"""
url_detector.py

URL Detector
------------
Checks:
    - URL Blacklist
    - URL Shortener
    - IP Address URL
    - HTTPS
    - Typosquatting
    - Homoglyph/Punycode
    - Domain Age
    - Redirect Chain
    - URL Length

Input:
    Parsed JSON from output.py

Output:
{
    "detector": "URL",
    "score": 75,
    "severity": "High",
    "reasons": [...]
}
"""


class URLDetector:

    def __init__(self):

        self.weights = {

            "blacklisted": 50,

            "shortener": 15,

            "ip_address": 30,

            "no_https": 15,

            "typosquatting": 30,

            "homoglyph": 25,

            "young_domain": 25,

            "long_url": 10,

            "redirect_chain": 10,

            "many_urls": 5

        }

    def detect(self, email_json):

        urls = email_json.get("urls", {})

        score = 0
        reasons = []

        # ----------------------------------
        # Number of URLs
        # ----------------------------------

        url_count = urls.get("url_count", 0)

        if url_count > 10:

            score += self.weights["many_urls"]

            reasons.append(f"Contains {url_count} URLs")

        # ----------------------------------
        # Blacklisted URL
        # ----------------------------------

        if urls.get("blacklisted", False):

            score += self.weights["blacklisted"]

            reasons.append("Blacklisted URL detected")

        # ----------------------------------
        # URL Shortener
        # ----------------------------------

        if urls.get("shortener_used", False):

            score += self.weights["shortener"]

            reasons.append("URL shortener used")

        # ----------------------------------
        # IP Address URL
        # ----------------------------------

        if urls.get("ip_address_url", False):

            score += self.weights["ip_address"]

            reasons.append("URL uses an IP address")

        # ----------------------------------
        # HTTPS
        # ----------------------------------

        if not urls.get("https", True):

            score += self.weights["no_https"]

            reasons.append("URL does not use HTTPS")

        # ----------------------------------
        # Typosquatting
        # ----------------------------------

        if urls.get("typosquatting", False):

            score += self.weights["typosquatting"]

            reasons.append("Typosquatting detected")

        # ----------------------------------
        # Homoglyph / Punycode
        # ----------------------------------

        if urls.get("homoglyph", False):

            score += self.weights["homoglyph"]

            reasons.append("Homoglyph/Punycode detected")

        # ----------------------------------
        # Domain Age
        # ----------------------------------

        domain_age = urls.get("domain_age_days", 9999)

        if domain_age < 30:

            score += self.weights["young_domain"]

            reasons.append(
                f"Very new domain ({domain_age} days old)"
            )

        # ----------------------------------
        # URL Length
        # ----------------------------------

        longest = urls.get("longest_url_length", 0)

        if longest > 100:

            score += self.weights["long_url"]

            reasons.append(
                f"Very long URL ({longest} characters)"
            )

        # ----------------------------------
        # Redirects
        # ----------------------------------

        redirects = urls.get("redirect_count", 0)

        if redirects > 3:

            score += self.weights["redirect_chain"]

            reasons.append(
                f"Redirect chain ({redirects})"
            )

        score = min(score, 100)

        return {

            "detector": "URL",

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