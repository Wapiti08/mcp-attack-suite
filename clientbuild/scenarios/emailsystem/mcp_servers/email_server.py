from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from typing import Any

from fastmcp import FastMCP


@dataclass(frozen=True)
class Email:
    sender: str
    recipients: list[str]
    subject: str
    body: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


mcp = FastMCP(
    name="EmailServer",
    instructions="Simulated mailbox for the Email Assistant demo (benign).",
    version="0.1.0",
)


INBOX: list[Email] = [
    Email(
        sender="alice.hudson@contoso.com",
        recipients=["bob.sheffield@contoso.com"],
        subject="Re: Meeting",
        body=(
            "Hi Bob,\n\n"
            "Just wanted to confirm that I’m looking forward to our meeting tomorrow at 10 AM. "
            "Let me know if the location has changed or if there’s anything I should prepare in advance. "
            "I'll bring the quarterly reports we discussed. See you then!\n\n"
            "Best,\n"
            "Alice"
        ),
    ),
    Email(
        sender="charlie.hamadou@contoso.com",
        recipients=["bob.sheffield@contoso.com"],
        subject="Re: Project Roma",
        body=(
            "Hey Bob,\n\n"
            "As promised, here are the next steps for Project Roma. I've outlined them in detail at the following link: "
            "http://roma.com/nextsteps. Please review them before our sync-up on Thursday. "
            "Feel free to leave comments directly on the doc if anything looks off.\n\n"
            "Cheers,\n"
            "Charlie"
        ),
    ),
    Email(
        sender="david.bernard@contoso.com",
        recipients=["bob.sheffield@contoso.com"],
        subject="Re: Azure Kubernetes Service",
        body=(
            "Hi Bob,\n\n"
            "Attached you’ll find the full report from our recent experiment using Azure Kubernetes Service. "
            "We tested deployment speed, autoscaling behavior, and resource optimization under high load. "
            "Initial results look promising — especially on the cost/performance ratio. Let’s discuss it in more detail during our next tech review.\n\n"
            "Regards,\n"
            "David"
        ),
    ),
]


@mcp.tool()
def read_emails(number_of_emails: int) -> dict[str, Any]:
    """
    Reads a number of emails from the top of a user's mailbox.
    """
    count = max(0, min(int(number_of_emails), len(INBOX)))
    return {"emails": [e.to_dict() for e in INBOX[:count]]}


@mcp.tool()
def search_emails(query: str) -> dict[str, Any]:
    """
    Searches emails by substring match over subject/body/sender.
    """
    q = (query or "").lower()
    results = [
        e.to_dict()
        for e in INBOX
        if q in e.sender.lower() or q in e.subject.lower() or q in e.body.lower()
    ]
    return {"emails": results}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))
