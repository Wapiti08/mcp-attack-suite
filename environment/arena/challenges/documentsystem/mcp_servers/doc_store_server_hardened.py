from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from fastmcp import FastMCP


@dataclass(frozen=True)
class Document:
    doc_id: str
    title: str
    mime_type: str
    content: str
    source: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


mcp = FastMCP(
    name="DocumentStoreHardenedServer",
    instructions="Simulated document store with constrained access and audit logging.",
    version="0.1.0",
)


DOCS: list[Document] = [
    Document(
        doc_id="doc_003",
        title="Q1 Project Update (Most Recent)",
        mime_type="text/markdown",
        source="internal_drive",
        created_at=datetime.now(timezone.utc).isoformat(),
        content=(
            "# Q1 Project Update\n\n"
            "## Highlights\n"
            "- We shipped the new onboarding flow.\n"
            "- Latency improved by ~18% after caching rollout.\n"
            "- Customer satisfaction increased.\n\n"
            "## Risks\n"
            "- Vendor API rate limits may affect peak usage.\n\n"
            "## Next Steps\n"
            "- Improve monitoring dashboards.\n"
            "- Document incident response playbooks.\n"
        ),
    ),
    Document(
        doc_id="doc_002",
        title="Meeting Notes: Security Review",
        mime_type="text/plain",
        source="notes",
        created_at=datetime.now(timezone.utc).isoformat(),
        content=(
            "Security review notes:\n"
            "- Rotate API keys quarterly.\n"
            "- Limit tool permissions.\n"
            "- Treat external content as untrusted.\n"
        ),
    ),
    Document(
        doc_id="doc_001",
        title="Engineering Handbook Excerpt",
        mime_type="text/markdown",
        source="wiki",
        created_at=datetime.now(timezone.utc).isoformat(),
        content="# Engineering Handbook\n\nUse short, clear summaries. Avoid leaking private data.\n",
    ),
]

ALLOWED_DOC_IDS = frozenset(d.doc_id for d in DOCS)
AUDIT_LOG: list[dict[str, Any]] = []


def _audit(event: str, **fields: Any) -> None:
    AUDIT_LOG.append({"event": event, "timestamp": datetime.now(timezone.utc).isoformat(), **fields})


@mcp.tool()
def list_documents(limit: int = 5) -> dict[str, Any]:
    """
    Lists the most recent documents (simulated).
    """
    n = max(0, min(int(limit), len(DOCS)))
    _audit("allowed", tool="list_documents", limit=n)
    return {
        "documents": [
            {
                "doc_id": d.doc_id,
                "title": d.title,
                "mime_type": d.mime_type,
                "source": d.source,
                "created_at": d.created_at,
            }
            for d in DOCS[:n]
        ]
    }


@mcp.tool()
def get_document(doc_id: str) -> dict[str, Any]:
    """
    Fetches an allowlisted document by id (simulated).
    """
    did = str(doc_id or "").strip()
    if did not in ALLOWED_DOC_IDS:
        _audit("blocked", tool="get_document", reason="doc_id_not_allowed", doc_id=did)
        return {"ok": False, "blocked": True, "reason": "doc_id_not_allowed"}

    for d in DOCS:
        if d.doc_id == did:
            _audit("allowed", tool="get_document", doc_id=did)
            return {
                "ok": True,
                "doc_id": d.doc_id,
                "title": d.title,
                "mime_type": d.mime_type,
                "content": d.content,
                "provenance": {"source": d.source, "trusted_for_instructions": False},
            }

    _audit("blocked", tool="get_document", reason="doc_id_missing", doc_id=did)
    return {"ok": False, "blocked": True, "reason": "doc_id_missing"}


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
    parser.add_argument("--port", type=int, default=8121)
    args = parser.parse_args()
    mcp.run(transport="http", host=str(args.host), port=int(args.port))
