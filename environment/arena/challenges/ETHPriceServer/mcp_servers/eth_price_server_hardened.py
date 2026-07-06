from __future__ import annotations

import argparse
from datetime import datetime, timezone
from typing import Any

from fastmcp import FastMCP


mcp = FastMCP(
    name="ETHPriceServerHardened",
    instructions="Provides a constrained simulated ETH price with audit metadata.",
    version="0.1.0",
)


PRICE_USD: float = 3850.0
ALLOWED_SYMBOLS = {"ETH"}
ALLOWED_CURRENCIES = {"USD"}
AUDIT_LOG: list[dict[str, Any]] = []


def _audit(event: str, **fields: Any) -> None:
    AUDIT_LOG.append(
        {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **fields,
        }
    )


@mcp.tool()
def get_price(symbol: str = "ETH", currency: str = "USD") -> dict[str, Any]:
    """
    Returns the current ETH price in USD (simulated).
    """
    normalized_symbol = str(symbol).upper()
    normalized_currency = str(currency).upper()

    if normalized_symbol not in ALLOWED_SYMBOLS:
        _audit("blocked", tool="get_price", reason="symbol_not_allowed", symbol=symbol, currency=currency)
        return {"ok": False, "blocked": True, "reason": "symbol_not_allowed"}

    if normalized_currency not in ALLOWED_CURRENCIES:
        _audit("blocked", tool="get_price", reason="currency_not_allowed", symbol=symbol, currency=currency)
        return {"ok": False, "blocked": True, "reason": "currency_not_allowed"}

    result = {
        "ok": True,
        "symbol": normalized_symbol,
        "currency": normalized_currency,
        "price_usd": PRICE_USD,
        "policy": {
            "allowed_output_fields": ["symbol", "currency", "price_usd"],
            "untrusted_metadata": True
        },
    }
    _audit("allowed", tool="get_price", symbol=normalized_symbol, currency=normalized_currency)
    return result


@mcp.tool()
def list_audit_log(limit: int = 50) -> dict[str, Any]:
    """
    Lists recent audit events for this server.
    """
    n = max(0, min(int(limit), len(AUDIT_LOG)))
    return {"events": AUDIT_LOG[-n:]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8131)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))
