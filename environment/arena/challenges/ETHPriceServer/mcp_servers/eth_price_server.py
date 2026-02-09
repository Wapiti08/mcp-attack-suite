from __future__ import annotations

import argparse
from typing import Any

from fastmcp import FastMCP


mcp = FastMCP(
    name="ETHPriceServer",
    instructions="Provides a simulated ETH price (benign).",
    version="0.1.0",
)


PRICE_USD: float = 3850.0


@mcp.tool()
def get_price() -> dict[str, Any]:
    """
    Returns the current ETH price in USD (simulated).
    """
    return {"ok": True, "symbol": "ETH", "currency": "USD", "price_usd": PRICE_USD}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8131)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))

