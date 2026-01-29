from __future__ import annotations

import argparse
import os
from typing import Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from fastmcp import FastMCP


DEFAULT_BASE_URL = "http://127.0.0.1:8200"
BASE_URL_ENV = "RESOURCESYSTEM_BASE_URL"

mcp = FastMCP(
    name="ExternalResourceFetcher",
    instructions="Fetches and extracts text from external resources (benign).",
    version="0.1.0",
)


def _base_url() -> str:
    return (os.getenv(BASE_URL_ENV) or DEFAULT_BASE_URL).rstrip("/") + "/"


def _fetch(url: str) -> tuple[str, bytes]:
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    ctype = resp.headers.get("content-type", "application/octet-stream")
    return ctype, resp.content


def _extract_text(content_type: str, content: bytes) -> str:
    ctype = (content_type or "").lower()
    if "text/html" in ctype:
        soup = BeautifulSoup(content, "lxml")
        return soup.get_text("\n", strip=True)
    if "application/json" in ctype:
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return repr(content[:2000])
    try:
        return content.decode("utf-8", errors="replace")
    except Exception:
        return repr(content[:2000])


@mcp.tool()
def fetch_external_text(path: str, variant: str = "clean") -> dict[str, Any]:
    """
    Fetches an external document (HTML/Markdown/JSON) and returns extracted text.
    """
    rel = (path or "").lstrip("/")
    url = urljoin(_base_url(), rel)
    if "?" in url:
        url = f"{url}&variant={variant}"
    else:
        url = f"{url}?variant={variant}"
    ctype, body = _fetch(url)
    return {"ok": True, "url": url, "content_type": ctype, "text": _extract_text(ctype, body)}


@mcp.tool()
def fetch_external_image_ocr(path: str, variant: str = "clean") -> dict[str, Any]:
    """
    Fetches an external image and returns OCR text (simulated by a sidecar endpoint).
    """
    rel = (path or "").lstrip("/")
    image_url = urljoin(_base_url(), rel)
    ocr_url = urljoin(_base_url(), "media/ad_ocr.txt")
    ocr_url = f"{ocr_url}?variant={variant}"
    _, _ = _fetch(f"{image_url}?variant={variant}")
    ctype, ocr_body = _fetch(ocr_url)
    return {
        "ok": True,
        "image_url": f"{image_url}?variant={variant}",
        "ocr_url": ocr_url,
        "content_type": ctype,
        "ocr_text": ocr_body.decode("utf-8", errors="replace"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8201)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))
