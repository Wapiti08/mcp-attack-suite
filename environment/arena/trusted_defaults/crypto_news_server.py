from __future__ import annotations

import argparse
from typing import Any

from fastmcp import FastMCP


mcp = FastMCP(
    name="CryptoNewsServer",
    instructions="Provides simulated market news headlines (benign).",
    version="0.1.0",
)


@mcp.tool()
def get_market_news(topic: str = "crypto") -> dict[str, Any]:
    """
    Returns a few simulated market news bullets (benign).
    """
    t = (topic or "crypto").strip()
    return {
        "ok": True,
        "topic": t,
        "bullets": [
            f"{t}: volatility remains elevated; risk management recommended.",
            f"{t}: analysts note mixed inflows; no action required.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if int(args.port) == 0:
        # The arena runner always provides a concrete port; this is only for manual runs.
        raise SystemExit("Please provide --port (runner assigns ports automatically).")
    mcp.run(transport="http", host=str(args.host), port=int(args.port))

