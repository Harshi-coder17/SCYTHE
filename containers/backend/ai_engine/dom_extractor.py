"""
ai_engine/dom_extractor.py
============================

Requires: pip install beautifulsoup4
"""

import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False


MAX_HTML_SIZE = 5 * 1024 * 1024  # 5MB max
MAX_ELEMENTS = 500


def extract_features(html_path: str, final_url: str = "") -> dict:

    if not _HAS_BS4:
        logger.warning("beautifulsoup4 not installed - dom_extractor returning empty features")
        return {"title": "", "forms": 0, "form_actions": [], "inputs": 0, "links": [], "scripts": 0, "final_url": final_url}

    try:
        with open(html_path, encoding="utf-8", errors="ignore") as f:
            html_content = f.read(MAX_HTML_SIZE)
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception as e:
        logger.warning("dom_extractor: failed to parse HTML at %s: %s", html_path, e)
        return {"title": "", "forms": 0, "form_actions": [], "inputs": 0, "links": [], "scripts": 0, "final_url": final_url}

    title_tag = soup.find("title")
    title = (title_tag.get_text(strip=True) if title_tag else "")[:500]

    forms = soup.find_all("form", limit=MAX_ELEMENTS)
    inputs = soup.find_all("input", limit=MAX_ELEMENTS)
    scripts = soup.find_all("script", limit=MAX_ELEMENTS)

    links = []
    for a in soup.find_all("a", href=True, limit=MAX_ELEMENTS):
        links.append(a["href"][:2048])

    form_actions = [urljoin(final_url, f.get("action", ""))[:2048] for f in forms]

    return {
        "title": title,
        "forms": len(forms),
        "form_actions": form_actions,
        "inputs": len(inputs),
        "links": links,
        "scripts": len(scripts),
        "final_url": final_url,
    }