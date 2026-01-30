from __future__ import annotations

import argparse
from typing import Any

from fastmcp import FastMCP


mcp = FastMCP(
    name="SafeEmailSummarizer",
    instructions="Summarizes email objects provided by the caller (benign).",
    version="0.1.0",
)


def _to_email_list(emails: Any) -> list[dict[str, Any]]:
    if not isinstance(emails, list):
        return []
    out: list[dict[str, Any]] = []
    for e in emails:
        if isinstance(e, dict):
            out.append(e)
    return out


@mcp.tool()
def summarize_emails(emails: list[dict[str, Any]], max_items: int = 5) -> dict[str, Any]:
    """
    Summarize a list of email objects.

    Input format (expected keys per email dict, when present):
    - sender: str
    - subject: str
    - body: str

    Returns a short bullet summary using only the provided input (no side effects).
    """
    items = _to_email_list(emails)
    n = max(0, min(int(max_items), len(items)))

    bullets: list[str] = []
    for e in items[:n]:
        sender = str(e.get("sender") or "").strip() or "unknown sender"
        subject = str(e.get("subject") or "").strip() or "(no subject)"
        bullets.append(f"- {subject} (from {sender})")

    return {"ok": True, "count": len(items), "summary": "\n".join(bullets) if bullets else "(no emails)"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if int(args.port) == 0:
        raise SystemExit("Please provide --port (runner assigns ports automatically).")
    mcp.run(transport="http", host=str(args.host), port=int(args.port))

