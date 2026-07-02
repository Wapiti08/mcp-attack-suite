from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml

# load bom config yaml file
DEFAULT_CONFIG_PATH = Path(__file__).with_name("semantic_bom_config.yaml")


@dataclass
class SemanticTool:
    name: str
    description: str
    input_schema: dict[str, Any]

    # agent-facing semantic interface
    instructions: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)

    # capability/security semantics
    high_risk_params: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    trust_boundary: str = "unknown"

    # implementation-derived vetting evidence
    has_policy_hook: bool = False
    has_audit_support: bool = False
    implementation_summary: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)



@dataclass
class SemanticMCPBOM:
    server_name: str
    source: str

    # agent-facing server-level metadata
    server_description: str = ""
    server_instructions: list[str] = field(default_factory=list)

    tools: list[SemanticTool] = field(default_factory=list) 


def load_semantic_bom_config(path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    with config_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)

def get_config_section(
    config: dict[str, Any],
    section: str,
    name: str,
) -> list[str]:
    return config.get(section, {}).get(name, [])


def build_semantic_bom(
    server_code: str | Path,
    schema: dict[str, Any],
    config: dict[str, Any] | None = None,
) -> SemanticMCPBOM:

    config = config or load_semantic_bom_config()

    if isinstance(server_code, Path):
        source_text = server_code.read_text(encoding="utf-8")
        server_name = server_code.stem
        source = str(server_code)
    else:
        source_text = server_code
        server_name = schema.get("_server_name", "inline_server")
        source = schema.get("_source", "inline")
    
    # server context
    raw_server_description = schema.get("description", "")
    server_description, server_instructions = split_description_and_instructions(
        raw_server_description,
        config,
    )

    # tool context
    tools: list[SemanticTool] = []

    for tool in schema.get("tools", []):
        name = tool.get("name", "")
        raw_description = tool.get("description", "")
        input_schema = tool.get("inputSchema", {})

        description, instructions = split_description_and_instructions(
            raw_description,
            config,
        )

        