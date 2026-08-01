# email_engine/__init__.py
# V10 Email Architecture — Email collection & processing pipeline package.
#
# Modules:
#   poller.py             → Continuously polls Gmail / Outlook IMAP for new emails.
#   collector.py          → Fetches complete raw RFC822 email from IMAP.
#   parser.py             → Converts raw bytes into structured parsed.json.
#   url_extraction.py     → Extracts, decodes, and normalises all URLs.
#   attachment_handler.py → Extracts attachments to /shared/emails/{id}/attachments/
