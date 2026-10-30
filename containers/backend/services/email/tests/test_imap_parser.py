"""Offline MIME parser fixtures. Importing this module never opens a mailbox."""
from email.message import EmailMessage
from unittest.mock import patch

from services.email.email_collector import parse_raw_email


def test_current_email_parser_pipeline_is_offline_and_structured():
    message = EmailMessage()
    message["From"] = "Fixture Sender <sender@example.test>"
    message["To"] = "recipient@example.test"
    message["Subject"] = "Offline fixture"
    message["Message-ID"] = "<offline-fixture@example.test>"
    message["Authentication-Results"] = "fixture; spf=pass; dkim=pass; dmarc=pass"
    message.set_content("This is a local parser fixture. No mailbox is contacted.")
    # DNS enrichment is external to parser behavior and explicitly unavailable here.
    with patch("services.email.parser.domain_parser.DomainParser.get_mx_records", return_value=None), \
         patch("services.email.parser.domain_parser.DomainParser.check_dnssec", return_value=None), \
         patch("imaplib.IMAP4_SSL", side_effect=AssertionError("Tests must not contact IMAP")):
        result = parse_raw_email(message.as_bytes())
    assert set(result) == {"metadata", "authentication", "received_chain", "domain", "attachments", "content"}
    assert result["metadata"]["from_address"] == "sender@example.test"
    assert result["metadata"]["subject"] == "Offline fixture"
    assert result["attachments"]["attachment_count"] == 0
