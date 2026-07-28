"""
services/email/email_collector.py
===================================
V10 Email Architecture — Email Collection + Parse Step

Converts raw RFC822 email bytes into a structured parsed.json saved to
the shared volume at: /shared/emails/{email_id}/parsed.json

This is the bridge between the IMAP poller (fetchers/imap_poller.py) and
the Celery analysis chord. The API receives the email_id and this module
ensures the parsed.json exists before tasks are fired.

Data shape produced (mirrors imap_parser_with_poller.py in Output/):

    {
        "metadata":        MetadataParser.parse(raw_email),
        "authentication":  AuthenticationParser.parse(raw_email),
        "received_chain":  ReceivedChainParser.parse(raw_email),
        "domain":          DomainParser.parse(raw_email),
        "attachments":     AttachmentParser.parse(raw_email),
        "content":         ContentParser.parse(raw_email),
    }
"""

import json
import logging
import os

from services.email.parser.metadata_parser import MetadataParser
from services.email.parser.authentication_parser import AuthenticationParser
from services.email.parser.received_chain_parser import ReceivedChainParser
from services.email.parser.domain_parser import DomainParser
from services.email.parser.attachement_parser import AttachmentParser
from services.email.parser.content_parser import ContentParser

logger = logging.getLogger(__name__)


def parse_raw_email(raw_email: bytes) -> dict:
    """
    Run all 6 parsers on raw RFC822 email bytes and return a
    unified structured email dictionary.
    """
    return {
        "metadata":       MetadataParser.parse(raw_email),
        "authentication": AuthenticationParser.parse(raw_email),
        "received_chain": ReceivedChainParser.parse(raw_email),
        "domain":         DomainParser.parse(raw_email),
        "attachments":    AttachmentParser.parse(raw_email),
        "content":        ContentParser.parse(raw_email),
    }


def save_parsed_email(email_id: str, raw_email: bytes, shared_dir: str = "/shared/scans") -> str:
    """
    Parse raw email bytes and persist the result as parsed.json
    under /shared/emails/{email_id}/parsed.json.

    Returns the path to the saved file.
    """
    email_dir = os.path.join(shared_dir, "emails", email_id)
    os.makedirs(email_dir, exist_ok=True)

    parsed = parse_raw_email(raw_email)

    output_path = os.path.join(email_dir, "parsed.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2, ensure_ascii=False)

    logger.info("Parsed email saved email_id=%s path=%s", email_id, output_path)
    return output_path
