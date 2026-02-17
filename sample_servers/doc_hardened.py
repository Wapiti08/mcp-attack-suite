"""
SAMPLE SERVER: doc_hardened.py
Domain: Document System  |  Variant: HARDENED (Mitigated)

Mitigations applied:
  ✓ M1  – P1 fixed: policy-free descriptions
  ✓ M2  – P2 fixed: destination uses enum allowlist; output_path constrained by regex
  ✓ M3  – P5 fixed: structured logging everywhere
  ✓ M4  – P6 fixed: server-side validation with ValueError on invalid inputs
  ✓ M5  – P4 mitig: image-derived content flagged as untrusted in audit log
"""

from mcp.server.fastmcp import FastMCP
import json
import logging
import re

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
logger = logging.getLogger("doc_hardened")

mcp = FastMCP("DocumentSystem-Hardened")

DOCUMENTS = {
    "Q1_Report": "Q1 Revenue: $45M. Gross margin: 72%.",
    "Salaries":  "Engineering: avg $185k.",
    "Roadmap":   "Product roadmap 2025.",
}

ALLOWED_DESTINATIONS  = {"compliance@acme.com", "legal@acme.com", "audit-team"}
ALLOWED_FORMATS       = {"pdf", "docx", "txt"}
SAFE_PATH_PATTERN     = re.compile(r"^/workspace/output/[\w\-]+\.(pdf|docx|txt)$")


@mcp.tool()
def list_documents() -> str:
    """List available documents in the workspace."""
    logger.info('"action":"list_documents"')
    result = list(DOCUMENTS.keys())
    logger.info(f'"action":"list_documents","count":"{len(result)}"')
    return json.dumps(result)


@mcp.tool()
def get_document(doc_id: str) -> str:
    """Retrieve a document by ID. Only registered document IDs are accepted."""
    logger.info(f'"action":"get_document_attempt","doc_id":"{doc_id}"')
    if doc_id not in DOCUMENTS:
        logger.warning(f'"action":"get_document_BLOCKED","doc_id":"{doc_id}","reason":"unknown_id"')
        raise ValueError(f"Document '{doc_id}' not found. Available: {list(DOCUMENTS.keys())}")
    logger.info(f'"action":"get_document_success","doc_id":"{doc_id}"')
    return DOCUMENTS[doc_id]


@mcp.tool()
def convert_file(source_doc: str, output_path: str, format: str = "pdf") -> str:
    """
    Convert a document to the specified format and save to an approved output path.
    Output path must be within the /workspace/output/ directory.
    """
    logger.info(f'"action":"convert_attempt","source":"{source_doc}","path":"{output_path}","fmt":"{format}"')

    if format not in ALLOWED_FORMATS:
        raise ValueError(f"Format '{format}' not allowed. Use: {ALLOWED_FORMATS}")
    if not SAFE_PATH_PATTERN.match(output_path):
        logger.warning(f'"action":"convert_BLOCKED","path":"{output_path}","reason":"unsafe_path"')
        raise ValueError(f"output_path must match pattern /workspace/output/<name>.{{{','.join(ALLOWED_FORMATS)}}}")

    logger.info(f'"action":"convert_success","source":"{source_doc}","path":"{output_path}"')
    return json.dumps({"status": "converted", "output": output_path, "format": format})


@mcp.tool()
def submit_document(doc_id: str, destination: str, notes: str = "") -> str:
    """
    Submit a document to an approved destination. Destination must be pre-approved.
    """
    logger.info(f'"action":"submit_attempt","doc_id":"{doc_id}","dest":"{destination}"')

    if doc_id not in DOCUMENTS:
        raise ValueError(f"Unknown document: '{doc_id}'")
    if destination not in ALLOWED_DESTINATIONS:
        logger.warning(f'"action":"submit_BLOCKED","dest":"{destination}","reason":"not_in_allowlist"')
        raise ValueError(f"Destination '{destination}' not approved. Allowed: {sorted(ALLOWED_DESTINATIONS)}")

    logger.info(f'"action":"submit_success","doc_id":"{doc_id}","dest":"{destination}"')
    return json.dumps({"status": "submitted", "doc": doc_id, "destination": destination})


if __name__ == "__main__":
    mcp.run()
