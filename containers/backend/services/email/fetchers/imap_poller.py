import imaplib
import email
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


class IMAPFetcher:

    def __init__(
        self,
        imap_host,
        email_address,
        access_token,
        poll_interval=30,
    ):
        self.imap_host = imap_host
        self.email_address = email_address
        self.access_token = access_token
        self.poll_interval = poll_interval
        self.imap = None

        # Keeps track of emails already processed
        self.processed = set()

    def connect(self):

        self.imap = imaplib.IMAP4_SSL(
            self.imap_host,
            993
        )

        auth_string = (
            f"user={self.email_address}\x01"
            f"auth=Bearer {self.access_token}\x01\x01"
        )

        self.imap.authenticate(
            "XOAUTH2",
            lambda _: auth_string.encode()
        )

        self.imap.select("INBOX")

        logging.info("Connected.")

    def disconnect(self):

        if self.imap:
            self.imap.logout()

    def fetch_latest(self):

        status, data = self.imap.search(
            None,
            "ALL"
        )

        if status != "OK":
            return None

        ids = data[0].split()

        if not ids:
            return None

        latest = ids[-1]

        if latest in self.processed:
            return None

        status, msg = self.imap.fetch(
            latest,
            "(RFC822)"
        )

        if status != "OK":
            return None

        message = email.message_from_bytes(
            msg[0][1]
        )

        self.processed.add(latest)

        return message

    def mark_seen(self, message_uid):

        self.imap.store(
            message_uid,
            "+FLAGS",
            "\\Seen"
        )

    def poll(self):

        logging.info("Polling started...")

        while True:

            try:

                message = self.fetch_latest()

                if message:

                    logging.info(
                        "New email received."
                    )

                    yield message

            except Exception as e:

                logging.exception(e)

            time.sleep(
                self.poll_interval
            )


#######################################################
# Example usage
#######################################################

if __name__ == "__main__":

    EMAIL = "user@example.com"

    ACCESS_TOKEN = "YOUR_ACCESS_TOKEN"

    HOST = "imap.gmail.com"

    fetcher = IMAPFetcher(
        HOST,
        EMAIL,
        ACCESS_TOKEN,
        poll_interval=30,
    )

    fetcher.connect()

    try:

        for message in fetcher.poll():

            print(
                "Subject:",
                message["Subject"]
            )

            print(
                "Message-ID:",
                message["Message-ID"]
            )

        

    finally:

        fetcher.disconnect()