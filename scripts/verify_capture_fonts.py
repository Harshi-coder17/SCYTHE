"""Verify offline multilingual screenshot glyph coverage inside a sandbox image."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import subprocess

SAMPLES = {"zh-cn": "安全登录验证", "ja": "安全なログイン画面", "ko": "안전한로그인화면",
           "th": "เข้าสู่ระบบอย่างปลอดภัย", "hi": "सुरक्षित लॉगिन", "ar": "تسجيل الدخول الآمن", "emoji": "🔒"}


def covered(char: str, ranges: str) -> bool:
    point = ord(char)
    for item in ranges.split():
        ends = item.split("-", 1)
        low = int(ends[0], 16)
        high = int(ends[-1], 16)
        if low <= point <= high:
            return True
    return False


def coverage() -> dict:
    result = {}
    for lang, text in SAMPLES.items():
        pattern = "Noto Color Emoji" if lang == "emoji" else f":lang={lang}"
        fields = subprocess.check_output(
            ["fc-match", "-f", "%{family}\n%{file}\n", pattern], text=True
        ).splitlines()
        family, font = fields[0], fields[1]
        ranges = subprocess.check_output(["fc-query", "-f", "%{charset}", font], text=True)
        missing = [f"U+{ord(char):04X}" for char in text if not covered(char, ranges)]
        result[lang] = {"family": family, "font_file": font, "missing_codepoints": missing}
    return result


async def render(output: Path) -> dict:
    from playwright.async_api import async_playwright

    html = '<!doctype html><meta charset="utf-8"><style>body{font:44px sans-serif;padding:24px}p{margin:24px}</style>'
    html += "".join(f'<p lang="{lang}">{text}</p>' for lang, text in SAMPLES.items())
    (output / "fixture.html").write_text(html, encoding="utf-8")
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        try:
            page = await browser.new_page(viewport={"width": 960, "height": max(560, len(SAMPLES) * 100 + 80)})
            await page.set_content(html, wait_until="load")
            await page.evaluate("document.fonts.ready")
            await page.screenshot(path=str(output / "fixture.png"))
        finally:
            await browser.close()
    return {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
            for name in ("fixture.html", "fixture.png")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    fonts = coverage()
    hashes = asyncio.run(render(args.output_dir))
    valid = all(not item["missing_codepoints"] for item in fonts.values())
    report = {"valid": valid, "fonts": fonts, "fixture_checksums": hashes,
              "scope": "Offline browser fixture; no external target or network required"}
    (args.output_dir / "verification.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps({"valid": valid, "missing_codepoints": {
        lang: item["missing_codepoints"] for lang, item in fonts.items()}}))
    raise SystemExit(0 if valid else 1)


if __name__ == "__main__":
    main()
