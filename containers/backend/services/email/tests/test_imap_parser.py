import os
import json
import time
import imaplib

from dotenv import load_dotenv



from email_security_engine.parser.metadata_parser import MetadataParser
from email_security_engine.parser.authentication_parser import AuthenticationParser
from email_security_engine.parser.received_chain_parser import ReceivedChainParser
from email_security_engine.parser.domain_parser import DomainParser
from email_security_engine.parser.attachement_parser import AttachmentParser
from email_security_engine.parser.content_parser import ContentParser


# =====================================================
# CONFIGURATION
# =====================================================

IMAP_SERVER = "imap.gmail.com"
load_dotenv()

EMAIL = os.getenv("E-mail")
APP_PASSWORD = os.getenv("App_Password")

POLL_INTERVAL = 30

OUTPUT_DIR = "parsed_emails"

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


# =====================================================
# CONNECT
# =====================================================

mailbox = imaplib.IMAP4_SSL(
    IMAP_SERVER
)

mailbox.login(
    EMAIL,
    APP_PASSWORD
)

mailbox.select("INBOX")

print("Connected to Gmail.")
print(f"Polling every {POLL_INTERVAL} seconds...\n")


processed_ids = set()


# =====================================================
# MAIN LOOP
# =====================================================

while True:

    try:

        status, messages = mailbox.search(
            None,
            "ALL"
        )

        if status != "OK":

            print("Failed to search mailbox.")

            time.sleep(POLL_INTERVAL)

            continue

        email_ids = messages[0].split()

        if not email_ids:

            time.sleep(POLL_INTERVAL)

            continue

        latest_id = email_ids[-1]

        if latest_id in processed_ids:

            time.sleep(POLL_INTERVAL)

            continue

        status, msg_data = mailbox.fetch(
            latest_id,
            "(RFC822)"
        )

        if status != "OK":

            time.sleep(POLL_INTERVAL)

            continue

        raw_email = msg_data[0][1]

        print(f"New Email UID: {latest_id.decode()}")

        ####################################################
        # Run all parsers
        ####################################################

        result = {

            "metadata":
                MetadataParser.parse(
                    raw_email
                ),

            "authentication":
                AuthenticationParser.parse(
                    raw_email
                ),

            "domain":
                DomainParser.parse(
                    raw_email
                ),

            "content":
                ContentParser.parse(
                    raw_email
                ),

            "received_chain":
                ReceivedChainParser.parse(
                    raw_email
                ),

            "attachments":
                AttachmentParser.parse(
                    raw_email
                )

        }

        ####################################################
        # Filename
        ####################################################

        message_id = (
            result["metadata"]
            .get("message_id")
        )

        if message_id:

            filename = (
                message_id
                .replace("<", "")
                .replace(">", "")
                .replace("@", "_")
                .replace("/", "_")
                .replace("\\", "_")
            )

        else:

            filename = (
                f"email_{latest_id.decode()}"
            )

        path = os.path.join(
            OUTPUT_DIR,
            filename + ".json"
        )

        ####################################################
        # Save JSON
        ####################################################

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                result,
                f,
                indent=4,
                ensure_ascii=False
            )

        print(
            f"Saved -> {path}\n"
        )

        processed_ids.add(
            latest_id
        )

    except KeyboardInterrupt:

        print("\nStopping...")

        mailbox.logout()

        break

    except Exception as e:

        print(e)

        try:
            mailbox.noop()
        except:
            mailbox = imaplib.IMAP4_SSL(
                IMAP_SERVER
            )

            mailbox.login(
                EMAIL,
                APP_PASSWORD
            )

            mailbox.select(
                "INBOX"
            )

    time.sleep(
        POLL_INTERVAL
    )