"""
test_all_detectors.py

Runs every detector on every NEW parsed email JSON.
Prints results to the terminal and saves them as JSON reports.
"""

import json
from pathlib import Path

from email_security_engine.detectors.authentication_detector import AuthenticationDetector
from email_security_engine.detectors.content_detector import ContentDetector
from email_security_engine.detectors.identity_detector import IdentityDetector
from email_security_engine.detectors.infrastructure_detector import InfrastructureDetector


# ------------------------------------------------------------
# Project Directories
# ------------------------------------------------------------

# Project Root (E-mail/)
PROJECT_ROOT = Path(__file__).resolve().parents[2]

PARSED_DIR = PROJECT_ROOT / "parsed_emails"

REPORT_DIR = PROJECT_ROOT / "reports"
RESULTS_DIR = REPORT_DIR / "detector_results"

PROCESSED_FILE = REPORT_DIR / "processed.json"


# ------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------

def print_result(result):
    print("=" * 70)
    print(f"Detector : {result['detector']}")
    print(f"Score    : {result['score']}")
    print(f"Severity : {result['severity']}")

    print("\nReasons:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(f"  • {reason}")
    else:
        print("  None")

    print()


def get_overall_severity(score):
    """
    Convert total score into an overall severity level.
    Modify these thresholds as needed.
    """

    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 20:
        return "Low"
    else:
        return "Safe"


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    REPORT_DIR.mkdir(exist_ok=True)
    RESULTS_DIR.mkdir(exist_ok=True)

    if PROCESSED_FILE.exists():
        with open(PROCESSED_FILE, "r") as f:
            processed = set(json.load(f))
    else:
        processed = set()

    detectors = [
        AuthenticationDetector(),
        IdentityDetector(),
        InfrastructureDetector(),
        ContentDetector(),
    ]

    json_files = sorted(PARSED_DIR.glob("*.json"))

    if not json_files:
        print("No parsed emails found.")
        return

    for json_file in json_files:

        if json_file.name in processed:
            continue

        print(f"\nProcessing: {json_file.name}")

        with open(json_file, "r") as f:
            email = json.load(f)

        total_score = 0
        detector_results = []

        for detector in detectors:

            result = detector.detect(email)

            total_score += result["score"]

            detector_results.append(result)

            print_result(result)

        overall_severity = get_overall_severity(total_score)

        print("=" * 70)
        print(f"Total Score      : {total_score}")
        print(f"Overall Severity : {overall_severity}")
        print("=" * 70)

        # ----------------------------------------------------
        # Save report
        # ----------------------------------------------------

        report = {
            "email": json_file.name,
            "total_score": total_score,
            "overall_severity": overall_severity,
            "detectors": detector_results,
        }

        report_path = RESULTS_DIR / f"{json_file.stem}_report.json"

        with open(report_path, "w") as f:
            json.dump(report, f, indent=4)

        print(f"Report saved: {report_path}")

        processed.add(json_file.name)

    with open(PROCESSED_FILE, "w") as f:
        json.dump(sorted(processed), f, indent=4)


if __name__ == "__main__":
    main()