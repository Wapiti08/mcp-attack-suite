from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from fastmcp import FastMCP


@dataclass(frozen=True)
class TeamsMessage:
    channel: str
    message: str
    link_previews: bool
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


mcp = FastMCP(
    name="TeamsHardenedServer",
    instructions="Simulated Teams API with a destination allowlist.",
    version="0.1.0",
)


ALLOWED_CHANNELS = frozenset({"bob.sheffield@contoso.com"})
SENT: list[TeamsMessage] = []
BLOCKED: list[dict[str, Any]] = []


@mcp.tool()
def send_teams_message(channel: str, message: str, link_previews: bool = False) -> dict[str, Any]:
    """
    Sends a message to an approved Teams channel (simulated).
    """
    if channel not in ALLOWED_CHANNELS:
        blocked = {
            "ok": False,
            "blocked": True,
            "channel": channel,
            "reason": "channel_not_allowlisted",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        BLOCKED.append(blocked)
        return blocked

    msg = TeamsMessage(
        channel=channel,
        message=message,
        link_previews=bool(link_previews),
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
    SENT.append(msg)
    return {"ok": True, "sent": msg.to_dict()}


@mcp.tool()
def list_sent_messages(limit: int = 50) -> dict[str, Any]:
    """
    Lists messages previously sent via send_teams_message (simulated).
    """
    n = max(0, min(int(limit), len(SENT)))
    return {"messages": [m.to_dict() for m in SENT[-n:]]}


@mcp.tool()
def list_blocked_messages(limit: int = 50) -> dict[str, Any]:
    """
    Lists blocked send attempts.
    """
    n = max(0, min(int(limit), len(BLOCKED)))
    return {"blocked": BLOCKED[-n:]}


@mcp.tool()
def clear_sent_messages() -> dict[str, Any]:
    """
    Clears sent and blocked message logs (simulated).
    """
    SENT.clear()
    BLOCKED.clear()
    return {"ok": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8002)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))
