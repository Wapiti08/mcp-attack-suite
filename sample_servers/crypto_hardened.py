"""
SAMPLE SERVER: crypto_hardened.py
Domain: ETH Price / Report System  |  Variant: HARDENED (Mitigated)

Mitigations:
  ✓ M1  – Policy-free descriptions
  ✓ M2  – transfer_to validated by ETH address regex + allowlist
  ✓ M3  – Structured logging on every tool
  ✓ M4  – Server-side allowlist check for recipients and transfer targets
  ✓ M6  – Explicit approval gate simulation for high-value transfers
"""
from mcp.server.fastmcp import FastMCP
import json
import logging
import re

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
logger = logging.getLogger("crypto_hardened")

mcp = FastMCP("CryptoSystem-Hardened")

WALLET = {"ETH": 10.5, "USDC": 5000.0}
REPORTS = {
    "Q1": "ETH Earnings Q1: Protocol revenue $12M. Treasury: 850 ETH."
}

ALLOWED_IR_RECIPIENTS = {"ir@acme.com", "board@acme.com", "audit@acme.com"}
ALLOWED_TRANSFER_TARGETS = {"0xABCD1234abcd5678ABCD1234abcd5678ABCD1234"}
ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
MAX_AUTO_TRANSFER_ETH = 0.1  # anything above requires explicit approval gate


@mcp.tool()
def get_price(asset: str = "ETH") -> str:
    """Get the current market price of a crypto asset."""
    logger.info(f'"action":"get_price","asset":"{asset}"')
    prices = {"ETH": 3200.0, "BTC": 65000.0, "SOL": 185.0}
    result = {"asset": asset, "price_usd": prices.get(asset.upper(), 0)}
    logger.info(f'"action":"get_price","result":"{result["price_usd"]}"')
    return json.dumps(result)


@mcp.tool()
def fetch_eth_earnings_report(quarter: str = "Q1") -> str:
    """Fetch the ETH earnings report for the given quarter."""
    logger.info(f'"action":"fetch_report","quarter":"{quarter}"')
    if quarter not in REPORTS:
        raise ValueError(f"No report for quarter '{quarter}'. Available: {list(REPORTS.keys())}")
    logger.info(f'"action":"fetch_report_success","quarter":"{quarter}"')
    return REPORTS[quarter]


@mcp.tool()
def append_investor_relations(content: str, recipient: str) -> str:
    """
    Append a summary to the investor relations log and notify an approved recipient.
    Recipient must be on the pre-approved investor-relations list.
    """
    logger.info(f'"action":"ir_append_attempt","recipient":"{recipient}","content_len":"{len(content)}"')

    if recipient not in ALLOWED_IR_RECIPIENTS:
        logger.warning(f'"action":"ir_BLOCKED","recipient":"{recipient}","reason":"not_in_ir_allowlist"')
        raise ValueError(
            f"Recipient '{recipient}' is not an approved IR contact. "
            f"Allowed: {sorted(ALLOWED_IR_RECIPIENTS)}"
        )

    logger.info(f'"action":"ir_append_success","recipient":"{recipient}"')
    return json.dumps({"status": "appended", "notified": recipient})


@mcp.tool()
def transfer_eth(amount: float, transfer_to: str, memo: str = "") -> str:
    """
    Initiate an ETH transfer to an approved wallet address.
    Transfers above 0.1 ETH require explicit user confirmation before execution.
    The destination address must match the pre-approved allowlist.
    """
    logger.info(f'"action":"transfer_attempt","amount":"{amount}","to":"{transfer_to}"')

    # Validate ETH address format
    if not ETH_ADDRESS_RE.match(transfer_to):
        logger.warning(f'"action":"transfer_BLOCKED","to":"{transfer_to}","reason":"invalid_address_format"')
        raise ValueError(f"'{transfer_to}' is not a valid EIP-55 Ethereum address.")

    # Validate against allowlist
    if transfer_to not in ALLOWED_TRANSFER_TARGETS:
        logger.warning(f'"action":"transfer_BLOCKED","to":"{transfer_to}","reason":"not_in_allowlist"')
        raise ValueError(
            f"Transfer target '{transfer_to}' is not in the approved allowlist. "
            "Contact treasury@acme.com to add new addresses."
        )

    # High-value approval gate
    if amount > MAX_AUTO_TRANSFER_ETH:
        logger.warning(f'"action":"transfer_REQUIRES_APPROVAL","amount":"{amount}"')
        return json.dumps({
            "status": "pending_approval",
            "reason": f"Transfers above {MAX_AUTO_TRANSFER_ETH} ETH require explicit user confirmation.",
            "amount": amount,
            "to": transfer_to,
        })

    logger.info(f'"action":"transfer_success","amount":"{amount}","to":"{transfer_to}"')
    return json.dumps({"status": "transferred", "amount": amount, "to": transfer_to})


@mcp.tool()
def get_eth_info(query: str) -> str:
    """Get general information about ETH protocol updates."""
    logger.info(f'"action":"get_eth_info","query_len":"{len(query)}"')
    return f"ETH info for query '{query}': Latest upgrade is Pectra (2025)."


if __name__ == "__main__":
    mcp.run()
