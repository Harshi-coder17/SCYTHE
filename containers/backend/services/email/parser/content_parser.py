import re

import mailparser

from bs4 import BeautifulSoup

from langdetect import detect

from confusable_homoglyphs import confusables


class ContentParser:

    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\']+'
    )

    @staticmethod
    def get_body(mail):

        body_text = ""
        html_body = ""

        if mail.text_plain:
            body_text = "\n".join(mail.text_plain)

        if mail.text_html:
            html_body = "\n".join(mail.text_html)

        return body_text, html_body

    @staticmethod
    def extract_urls(body_text, html_body):

        urls = set()

        # URLs from plain text
        urls.update(
            ContentParser.URL_PATTERN.findall(
                body_text
            )
        )

        # URLs from HTML
        if html_body:

            soup = BeautifulSoup(
                html_body,
                "html.parser"
            )

            for tag in soup.find_all(
                "a",
                href=True
            ):

                urls.add(tag["href"])

        return list(urls)

    @staticmethod
    def detect_language(body_text):

        if not body_text.strip():
            return None

        try:
            return detect(body_text)

        except Exception:
            return None

    @staticmethod
    def contains_homoglyph(text):

        if not text:
            return False

        try:

            return bool(
                confusables.is_confusable(text)
            )

        except Exception:

            return False

    @staticmethod
    def tracking_pixel_count(html_body):

        if not html_body:
            return 0

        soup = BeautifulSoup(
            html_body,
            "html.parser"
        )

        count = 0

        for img in soup.find_all("img"):

            width = str(
                img.get("width", "")
            )

            height = str(
                img.get("height", "")
            )

            style = (
                img.get("style", "")
                .replace(" ", "")
                .lower()
            )

            if (
                width == "1"
                and
                height == "1"
            ):

                count += 1

            elif (
                "width:1px" in style
                and
                "height:1px" in style
            ):

                count += 1

        return count

    @staticmethod
    def parse(raw_email):

        mail = mailparser.parse_from_bytes(
            raw_email
        )

        body_text, html_body = (
            ContentParser.get_body(mail)
        )

        urls = ContentParser.extract_urls(
            body_text,
            html_body
        )

        return {

            "body_text":
                body_text,

            "html_body":
                html_body,

            "language":
                ContentParser.detect_language(
                    body_text
                ),

            "link_mentioned":
                len(urls) > 0,

            "extracted_urls":
                urls,

            "homoglyph_in_subject_or_body":
                ContentParser.contains_homoglyph(
                    body_text
                ),

            "embedded_tracking_pixel_count":
                ContentParser.tracking_pixel_count(
                    html_body
                )
        }