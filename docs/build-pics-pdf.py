#!/usr/bin/env python3
"""Render docs/PICS.md to docs/PICS.pdf.

Needs the Python `markdown` package (pip install markdown) and a Chromium
browser (Chrome, Edge or Chromium) for the HTML-to-PDF step. Run it from
anywhere after regenerating docs/PICS.md:

    python docs/build-pics-pdf.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

import markdown

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "PICS.md")
TARGET = os.path.join(HERE, "PICS.pdf")

CSS = """
@page { size: Letter; margin: 18mm 16mm; }
body { font-family: "Segoe UI", Arial, sans-serif; font-size: 10pt; line-height: 1.4; color: #111; }
h1 { font-size: 18pt; border-bottom: 2px solid #333; padding-bottom: 4px; }
h2 { font-size: 13pt; margin-top: 18pt; border-bottom: 1px solid #999; page-break-after: avoid; }
h3 { font-size: 10.5pt; margin-top: 14pt; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0; page-break-inside: auto; }
tr { page-break-inside: avoid; }
th, td { border: 1px solid #bbb; padding: 3px 6px; text-align: left; vertical-align: top; }
th { background: #eee; }
code { font-family: Consolas, monospace; font-size: 9pt; }
blockquote { border-left: 3px solid #999; margin: 8pt 0; padding: 2pt 10pt; color: #333; }
a { color: #0645ad; text-decoration: none; }
"""

BROWSERS = [
    "chrome", "google-chrome", "chromium", "chromium-browser", "msedge",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def find_browser():
    for name in BROWSERS:
        path = shutil.which(name) or (name if os.path.isfile(name) else None)
        if path:
            return path
    return None


def main():
    with open(SOURCE, encoding="utf-8") as f:
        body = markdown.markdown(f.read(), extensions=["tables", "fenced_code"])
    # Links to repo files are relative; point them at GitHub for the PDF reader.
    body = body.replace('href="../', 'href="https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/blob/main/')
    html = ("<!DOCTYPE html><html><head><meta charset='utf-8'><title>B-SCHUB PICS</title>"
            "<style>" + CSS + "</style></head><body>" + body + "</body></html>")

    browser = find_browser()
    if not browser:
        sys.exit("error: no Chrome/Edge/Chromium found for the PDF step")
    # Edge on Windows can hand the job to an already-running process and
    # return at once, so wait for the PDF rather than trusting the exit.
    tmp = tempfile.mkdtemp()
    try:
        page = os.path.join(tmp, "PICS.html")
        with open(page, "w", encoding="utf-8") as f:
            f.write(html)
        if os.path.exists(TARGET):
            os.remove(TARGET)
        subprocess.run([browser, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                        "--user-data-dir=" + os.path.join(tmp, "profile"),
                        "--print-to-pdf=" + TARGET, "file:///" + page.replace("\\", "/")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            if os.path.exists(TARGET) and os.path.getsize(TARGET) > 0:
                break
            time.sleep(0.5)
        else:
            sys.exit("error: the browser did not write " + TARGET)
        time.sleep(1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("wrote", TARGET)


if __name__ == "__main__":
    main()
