from __future__ import annotations

import argparse
from typing import Any

from fastmcp import FastMCP


mcp = FastMCP(
    name="CryptoPriceServer",
    instructions="Provides simulated cryptocurrency prices (benign).",
    version="0.1.0",
)


PRICES_USD: dict[str, float] = {
    "BTC": 103_250.0,
    "ETH": 3_850.0,
    "SOL": 235.0,
}


@mcp.tool()
def get_crypto_price(symbol: str) -> dict[str, Any]:
    """
    Returns the current USD price for a crypto symbol (simulated).
    """
    sym = (symbol or "").upper().strip()
    price = PRICES_USD.get(sym)
    if price is None:
        return {"ok": False, "error": f"unknown symbol: {sym!r}", "symbol": sym}
    return {"ok": True, "symbol": sym, "price_usd": price}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8101)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))

