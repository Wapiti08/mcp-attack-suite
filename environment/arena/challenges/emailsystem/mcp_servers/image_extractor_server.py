from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
from typing import Any

from fastmcp import FastMCP


def _repo_root() -> Path:
    # environment/arena/challenges/emailsystem/mcp_servers/*.py -> parents[5] == repo root
    return Path(__file__).resolve().parents[5]


def _load_local_env() -> None:
    """
    Load `environment/arena/challenges/emailsystem/mcp_servers/.env` if present.
    This keeps vision/extraction config scoped to this tool server.
    """
    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception:
        return

    tool_dir = Path(__file__).resolve().parent
    load_dotenv(dotenv_path=tool_dir / ".env", override=False)


def _read_image_bytes(path: str) -> tuple[bytes, str]:
    p = Path(path)
    if not p.is_absolute():
        p = (_repo_root() / p).resolve()
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Image not found: {p}")
    data = p.read_bytes()

    ext = p.suffix.lower().lstrip(".")
    if ext in {"jpg", "jpeg"}:
        mime = "image/jpeg"
    elif ext == "webp":
        mime = "image/webp"
    elif ext == "gif":
        mime = "image/gif"
    else:
        mime = "image/png"
    return data, mime


def _vision_client_config() -> tuple[str, str | None, str | None]:
    model = os.getenv("IMAGE_EXTRACT_OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or ""
    base_url = os.getenv("IMAGE_EXTRACT_OPENAI_BASE_URL") or os.getenv("OPENAI_BASE_URL")
    api_key = os.getenv("IMAGE_EXTRACT_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not model:
        raise RuntimeError("Missing IMAGE_EXTRACT_OPENAI_MODEL (or OPENAI_MODEL). Put it in this folder's .env.")
    if not api_key:
        raise RuntimeError("Missing IMAGE_EXTRACT_OPENAI_API_KEY (or OPENAI_API_KEY). Put it in this folder's .env.")
    return model, base_url, api_key


mcp = FastMCP(
    name="ImageExtractorServer",
    instructions=(
        "Extracts text from images using an OpenAI-compatible multimodal model.\n"
    ),
    version="0.1.0",
)


@mcp.tool()
def extract_image_content(image_path: str, instruction: str = "Extract all readable text from the image verbatim.") -> dict[str, Any]:
    """
    Extract readable content from an image file on disk.

    This tool is intended to be used as a preprocessing step for multimodal email handling.
    """
    _load_local_env()
    model, base_url, api_key = _vision_client_config()

    data, mime = _read_image_bytes(image_path)
    b64 = base64.b64encode(data).decode("ascii")
    data_url = f"data:{mime};base64,{b64}"

    from openai import OpenAI  # type: ignore

    client = OpenAI(api_key=api_key, base_url=base_url, timeout=30.0, max_retries=0)
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": instruction},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            }
        ],
        max_tokens=400,
        temperature=0,
    )
    text = (resp.choices[0].message.content or "").strip()
    return {"text": text, "model": model, "base_url": base_url}


@mcp.tool()
def summarize_email(email: dict[str, Any], instruction: str = "Summarize the email briefly.") -> dict[str, Any]:
    """
    Summarize a single email object. If the email contains image attachments, uses a multimodal model.

    Expected email shape (from inbox_provider.read_emails):
      { "sender": str, "recipients": [str], "subject": str, "body": str, "attachments": [{ "path": str, ... }] }
    """
    _load_local_env()
    model, base_url, api_key = _vision_client_config()

    sender = str(email.get("sender") or "")
    subject = str(email.get("subject") or "")
    body = str(email.get("body") or "")
    attachments = email.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []

    image_paths: list[str] = []
    for a in attachments:
        if not isinstance(a, dict):
            continue
        p = a.get("path")
        mt = a.get("mime_type")
        if not isinstance(p, str) or not p:
            continue
        ext = Path(p).suffix.lower()
        is_image = (isinstance(mt, str) and mt.startswith("image/")) or ext in {".png", ".jpg", ".jpeg", ".webp", ".gif"}
        if is_image:
            image_paths.append(p)

    content: list[dict[str, Any]] = []
    content.append({"type": "text", "text": f"{instruction}\n\nFrom: {sender}\nSubject: {subject}\n\nBody:\n{body}".strip()})

    for p in image_paths:
        try:
            data, mime = _read_image_bytes(p)
        except Exception:
            continue
        b64 = base64.b64encode(data).decode("ascii")
        data_url = f"data:{mime};base64,{b64}"
        content.append({"type": "image_url", "image_url": {"url": data_url}})

    from openai import OpenAI  # type: ignore

    client = OpenAI(api_key=api_key, base_url=base_url, timeout=30.0, max_retries=0)
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": content}],
        max_tokens=300,
        temperature=0,
    )
    summary = (resp.choices[0].message.content or "").strip()
    return {"summary": summary, "used_multimodal": bool(image_paths), "model": model, "base_url": base_url}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8010)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))
