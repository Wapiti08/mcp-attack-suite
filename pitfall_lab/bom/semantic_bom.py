from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml

DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.yaml")


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


@dataclass(frozen=True)
class SemanticBOMConfig:
    field_variants: dict[str, list[str]] = field(default_factory=dict)
    high_risk_param_keywords: list[str] = field(default_factory=list)
    source_tool_keywords: list[str] = field(default_factory=list)
    sink_tool_keywords: list[str] = field(default_factory=list)
    instruction_markers: list[str] = field(default_factory=list)
    policy_markers: list[str] = field(default_factory=list)
    audit_markers: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SemanticBOMConfig":
        return cls(
            field_variants=_list_map(raw.get("field_variants", {})),
            high_risk_param_keywords=raw.get("keywords", {}).get("high_risk_params", []),
            source_tool_keywords=raw.get("keywords", {}).get("source_tools", []),
            sink_tool_keywords=raw.get("keywords", {}).get("sink_tools", []),
            instruction_markers=raw.get("markers", {}).get("instructions", []),
            policy_markers=raw.get("markers", {}).get("policy", []),
            audit_markers=raw.get("markers", {}).get("audit", []),
        )


def load_semantic_bom_config(path: str | Path | None = None) -> SemanticBOMConfig:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    with config_path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return SemanticBOMConfig.from_dict(raw)


def build_semantic_bom(
    server_code: str | Path,
    schema: dict[str, Any],
    config: SemanticBOMConfig | dict[str, Any] | None = None,
) -> SemanticMCPBOM:

    config = normalize_config(config)

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

        roles = infer_roles(name, raw_description, config)
        function_source = extract_function_source(source_text, name)

        tools.append(
            SemanticTool(
                name = name,
                description=description,
                instructions=instructions,
                examples = normalize_examples(tool.get("examples", [])),
                input_schema = input_schema,
                high_risk_params = infer_high_risk_params(input_schema, config),
                roles=roles,
                trust_boundary=infer_trust_boundary(roles),
                has_policy_hook=bool(instructions) or infer_policy_hook(
                    raw_description,
                    config,
                ),
                has_audit_support=infer_audit_support(function_source, config),
                implementation_summary="",
                evidence={
                    "raw_description": raw_description,
                    "function_source_available": bool(function_source),
                    "has_validation": infer_validation_support(function_source),
                    "has_allowlist": infer_allowlist_support(function_source),
                },
            )
        )

    return SemanticMCPBOM(
        server_name=server_name,
        source=source,
        server_description=server_description,
        server_instructions=server_instructions,
        tools=tools,
    )


def split_description_and_instructions(
    docstring: str,
    config: dict[str, Any],
) -> tuple[str, list[str]]:
    lines = [line.strip() for line in docstring.splitlines() if line.strip()]
    markers = get_config_section(config, "markers", "instructions")

    description_lines: list[str] = []
    instruction_lines: list[str] = []

    for line in lines:
        lowered = line.lower()
        if any(marker.lower() in lowered for marker in markers):
            instruction_lines.append(line)
        else:
            description_lines.append(line)
    
    return " ".join(description_lines), instruction_lines


def infer_high_risk_params(
    input_schema: dict[str, Any],
    config: SemanticBOMConfig,
) -> list[str]:
    properties = input_schema.get("properties", {})
    high_risk: list[str] = []

    for param_name in properties:
        lowered = param_name.lower()
        if any(
            keyword.lower() in lowered 
            for keyword in config.high_risk_param_keywords
        ):
            high_risk.append(param_name)
    
    return high_risk


def infer_roles(
    name: str,
    description: str,
    config: SemanticBOMConfig,
) -> list[str]:
    text = f"{name} {description}".lower()
    roles: list[str] = []

    if any(keyword_matches(text, keyword) for keyword in config.source_tool_keywords):
        roles.append("source")

    if any(keyword_matches(text, keyword) for keyword in config.sink_tool_keywords):
        roles.append("sink")

    if "image" in text or "ocr" in text:
        roles.append("transformer")

    return sorted(set(roles))


def keyword_matches(text: str, keyword: str) -> bool:
    escaped = re.escape(keyword.lower())
    if re.search(rf"(?<![a-z0-9_]){escaped}(?![a-z0-9_])", text):
        return True

    # Tool names often encode verbs as snake_case prefixes, e.g. read_emails.
    return f"{keyword.lower()}_" in text


def infer_trust_boundary(roles: list[str]) -> str:
    role_set = set(roles)

    if "source" in role_set and "sink" in role_set:
        return "source_and_sink"
    
    if "source" in role_set:
        return "untrusted_source"
    
    if "sink" in role_set:
        return "external_sink"
    
    if "transformer" in role_set:
        return "content_transformer"

    return "unknown"


def infer_policy_hook(
    description: str,
    config: SemanticBOMConfig,
)-> bool:
    lowered = description.lower()
    return any(marker.lower() in lowered for marker in config.policy_markers)


def infer_audit_support(
    function_source: str,
    config: SemanticBOMConfig,
) -> bool:
    lowered = function_source.lower()
    return any(marker.lower() in lowered for marker in config.audit_markers)


def infer_validation_support(function_source: str) -> bool:
    lowered = function_source.lower()
    validation_markers = [
        "raise valueerror",
        "raise validationerror",
        "not in allowed",
        "not_in_allowlist",
        "re.match",
        "re.fullmatch",
        ".match(",
        ".fullmatch(",
        "assert ",
    ]
    return any(marker in lowered for marker in validation_markers)


def infer_allowlist_support(function_source: str) -> bool:
    lowered = function_source.lower()
    allowlist_markers = [
        "allowed_",
        "allowlist",
        "allow-list",
        "approved",
        "pre-approved",
        "not in allowed",
        "not_in_allowlist",
    ]
    return any(marker in lowered for marker in allowlist_markers)


def extract_function_source(source_text: str, function_name: str) -> str:
    try:
        # abstract syntax tree
        tree = ast.parse(source_text)
    except SyntaxError:
        return ""

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        if node.name == function_name:
            return ast.get_source_segment(source_text, node) or ""

    return ""


def normalize_examples(raw_examples: Any) -> list[str]:
    if raw_examples is None:
        return []
    
    if isinstance(raw_examples, str):
        return [raw_examples]

    if isinstance(raw_examples, list):
        return [str(example) for example in raw_examples]

    return [str(raw_examples)]


def bom_to_dict(bom: SemanticMCPBOM) -> dict[str, Any]:
    return {
        "server_name": bom.server_name,
        "source": bom.source,
        "server_description": bom.server_description,
        "server_instructions": bom.server_instructions,
        "tools": [
            {
                "name": tool.name,
                "description": tool.description,
                "instructions": tool.instructions,
                "examples": tool.examples,
                "input_schema": tool.input_schema,
                "high_risk_params": tool.high_risk_params,
                "roles": tool.roles,
                "trust_boundary": tool.trust_boundary,
                "has_policy_hook": tool.has_policy_hook,
                "has_audit_support": tool.has_audit_support,
                "implementation_summary": tool.implementation_summary,
                "evidence": tool.evidence,
            }
            for tool in bom.tools
        ],
    }


def normalize_config(
    config: SemanticBOMConfig | dict[str, Any] | None,
) -> SemanticBOMConfig:
    if config is None:
        return load_semantic_bom_config()
    
    if isinstance(config, SemanticBOMConfig):
        return config

    return SemanticBOMConfig.from_dict(config)


def get_config_section(
    config: SemanticBOMConfig | dict[str, Any],
    section: str,
    name: str,
) -> list[str]:
    """Compatibility helper for older callers that still expect section lookup."""
    if isinstance(config, dict):
        value = config.get(section, {}).get(name, [])
        return _string_list(value)

    mapping = {
        ("keywords", "high_risk_params"): config.high_risk_param_keywords,
        ("keywords", "source_tools"): config.source_tool_keywords,
        ("keywords", "sink_tools"): config.sink_tool_keywords,
        ("markers", "instructions"): config.instruction_markers,
        ("markers", "policy"): config.policy_markers,
        ("markers", "audit"): config.audit_markers,
    }

    return list(mapping.get((section, name), []))


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []

    return [str(item) for item in value]


def _list_map(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}

    return {
        str(key): _string_list(items)
        for key, items in value.items()
    }
