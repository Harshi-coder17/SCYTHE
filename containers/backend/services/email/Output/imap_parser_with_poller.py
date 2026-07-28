import json
import os
from datetime import datetime
from dotenv import load_dotenv

from email_security_engine.fetchers.imap_poller import IMAPFetcher

from email_security_engine.parser.metadata_parser import MetadataParser
from email_security_engine.parser.authentication_parser import AuthenticationParser
from email_security_engine.parser.received_chain_parser import ReceivedChainParser
from email_security_engine.parser.domain_parser import DomainParser
from email_security_engine.parser.attachement_parser import AttachmentParser
from email_security_engine.parser.content_parser import ContentParser


OUTPUT_DIR = "output"

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


def save_json(email_json):

    message_id = (
        email_json["metadata"]
        .get("message_id")
    )

    if message_id:

        filename = (
            message_id
            .replace("<", "")
            .replace(">", "")
            .replace("/", "_")
            .replace("\\", "_")
        ) + ".json"

    else:

        filename = (
            datetime.utcnow()
            .strftime("%Y%m%d_%H%M%S")
        ) + ".json"

    path = os.path.join(
        OUTPUT_DIR,
        filename
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            email_json,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"Saved -> {path}"
    )


def parse_email(raw_email):

    return {

        "metadata":
            MetadataParser.parse(
                raw_email
            ),

        "authentication":
            AuthenticationParser.parse(
                raw_email
            ),

        "received_chain":
            ReceivedChainParser.parse(
                raw_email
            ),

        "domain":
            DomainParser.parse(
                raw_email
            ),

        "attachments":
            AttachmentParser.parse(
                raw_email
            ),

        "content":
            ContentParser.parse(
                raw_email
            )
    }


def main():

    EMAIL = "YOUR_EMAIL"

    ACCESS_TOKEN = "YOUR_ACCESS_TOKEN"

    HOST = "imap.gmail.com"

    fetcher = IMAPFetcher(

        imap_host=HOST,

        email_address=EMAIL,

        access_token=ACCESS_TOKEN,

        poll_interval=30

    )

    fetcher.connect()

    try:

        for uid, raw_email in fetcher.poll():

            result = parse_email(
                raw_email
            )

            save_json(result)

            fetcher.mark_seen(uid)

    finally:

        fetcher.disconnect()


if __name__ == "__main__":

    main()