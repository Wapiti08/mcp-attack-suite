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
    name="TeamsServer",
    instructions="Simulated Teams API for the Email Assistant demo.",
    version="0.1.0",
)


SENT: list[TeamsMessage] = []


@mcp.tool()
def send_teams_message(channel: str, message: str, link_previews: bool = False) -> dict[str, Any]:
    """
    Sends a message to a Teams channel (simulated).
    """
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
def clear_sent_messages() -> dict[str, Any]:
    """
    Clears the sent message log (simulated).
    """
    SENT.clear()
    return {"ok": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8002)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))
