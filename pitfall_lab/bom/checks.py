from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from pitfall_lab.bom.semantic_bom import SemanticMCPBOM, SemanticTool


@dataclass
class BOMFinding:
    pitfall: str
    tool: str | None
    severity: str
    evidence: str
    required_fields: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


STATIC_CLASS_FIELDS = {
    "P1": ["descriptions", "tool_instructions", "policy_hooks"],
    "P2": ["schemas", "high_risk_params"],
    "P5": ["audit_support"],
    "P6": ["schemas", "high_risk_params"],
}

TRACE_CLASS_FIELDS = {
    "P3": ["capability_roles", "trust_boundary", "trace_provenance"],
    "P4": ["capability_roles", "trust_boundary", "trace_provenance"],
}

RISK_WEIGHTS = {
    "sink": 2,
    "source": 1,
    "transformer": 1,
    "high_risk_param": 2,
    "policy_hook": 2,
    "missing_audit": 1,
}

EXPOSURE_WEIGHTS = {
    "source": 1,
    "transformer": 1,
    "sink": 2,
    "high_risk_param": 2,
    "cross_boundary_path": 2,
}

CONTROL_COVERAGE_WEIGHTS = {
    "schema_constraint": 0.25,
    "validation": 0.30,
    "allowlist": 0.25,
    "audit": 0.10,
    "policy_hook": 0.10,
}

SCHEMA_CONSTRAINT_KEYS = {
    "const",
    "enum",
    "format",
    "maximum",
    "maxItems",
    "maxLength",
    "minimum",
    "minItems",
    "minLength",
    "pattern",
}

SAFETY_POLICY_MARKERS = [
    "approved",
    "pre-approved",
    "allowlist",
    "allow-list",
    "blocked",
    "must not be used as instructions",
    "untrusted",
    "validate",
    "validation",
    "confirmation",
    "redact",
    "minimiz",
]

UNSAFE_POLICY_MARKERS = [
    "always forward",
    "automatically forward",
    "never ask",
    "without confirmation",
    "without user confirmation",
    "do not ask",
]


def run_bom_checks(
    bom: SemanticMCPBOM,
    enabled_fields: list[str],
)-> list[BOMFinding]:
    fields = set(enabled_fields)
    findings: list[BOMFinding] = []

    for tool in bom.tools:
        if _enabled(fields, STATIC_CLASS_FIELDS["P1"]):
            findings.extend(check_p1(tool))

        if _enabled(fields, STATIC_CLASS_FIELDS["P2"]):
            findings.extend(check_p2(tool))

        if _enabled(fields, STATIC_CLASS_FIELDS["P5"]):
            findings.extend(check_p5(tool))

        if _enabled(fields, STATIC_CLASS_FIELDS["P6"]):
            findings.extend(check_p6(tool))

    return findings


def _enabled(enabled_fields: set[str], required_fields: list[str]) -> bool:
    return all(field in enabled_fields for field in required_fields)


def representable_classes(enabled_fields: list[str]) -> list[str]:
    fields = set(enabled_fields)
    covered = []

    for cls, required in {**STATIC_CLASS_FIELDS, **TRACE_CLASS_FIELDS}.items():
        if _enabled(fields, required):
            covered.append(cls)
    
    return sorted(covered)


def check_p1(tool: SemanticTool) -> list[BOMFinding]:
    if not tool.has_policy_hook:
        return []

    return [
        BOMFinding(
            pitfall="P1",
            tool=tool.name,
            severity="HIGH",
            evidence="Tool metadata contains imperative instructions or policy-like language.",
            required_fields=STATIC_CLASS_FIELDS["P1"],
        )
    ]


def check_p2(tool: SemanticTool) -> list[BOMFinding]:
    findings = []

    properties = tool.input_schema.get("properties", {})
    for param in tool.high_risk_params:
        schema = properties.get(param, {})
        has_constraint = any(
            key in schema
            for key in ["enum", "pattern", "maxLength", "format", "const"]
        )
        if not has_constraint:
            findings.append(
                BOMFinding(
                    pitfall="P2",
                    tool=tool.name,
                    severity="HIGH",
                    evidence=f"High-risk parameter `{param}` accepts unconstrained input.",
                    required_fields=STATIC_CLASS_FIELDS["P2"],
                )
            )

    return findings


def check_p5(tool: SemanticTool) -> list[BOMFinding]:
    if tool.has_audit_support:
        return []

    return [
        BOMFinding(
            pitfall="P5",
            tool=tool.name,
            severity="MEDIUM",
            evidence="Tool implementation has no detected audit/logging support.",
            required_fields=STATIC_CLASS_FIELDS["P5"],
        )
    ]


def check_p6(tool: SemanticTool) -> list[BOMFinding]:
    if not tool.high_risk_params:
        return []

    evidence = tool.evidence or {}
    has_validation = bool(evidence.get("has_validation", False))

    if has_validation:
        return []

    return [
        BOMFinding(
            pitfall="P6",
            tool=tool.name,
            severity="HIGH",
            evidence="Tool exposes high-risk parameters without validation evidence.",
            required_fields=STATIC_CLASS_FIELDS["P6"],
        )
    ]


def score_bom_risk(bom: SemanticMCPBOM) -> dict[str, Any]:
    tool_scores = []
    total = 0

    for tool in bom.tools:
        score = 0
        reasons = []

        for role in tool.roles:
            weight = RISK_WEIGHTS.get(role, 0)
            if weight:
                score += weight
                reasons.append(f"role:{role}+{weight}")

        if tool.high_risk_params:
            delta = RISK_WEIGHTS["high_risk_param"] * len(tool.high_risk_params)
            score += delta
            reasons.append(f"high_risk_params:{len(tool.high_risk_params)}+{delta}")

        if tool.has_policy_hook:
            score += RISK_WEIGHTS["policy_hook"]
            reasons.append("policy_hook+2")

        if not tool.has_audit_support:
            score += RISK_WEIGHTS["missing_audit"]
            reasons.append("missing_audit+1")

        total += score
        tool_scores.append(
            {
                "tool": tool.name,
                "score": score,
                "reasons": reasons,
            }
        )

    return {
        "server": bom.server_name,
        "risk_score": total,
        "tool_scores": tool_scores,
    }


def score_bom_decomposed(bom: SemanticMCPBOM) -> dict[str, Any]:
    exposure = _score_exposure(bom)
    coverage = _score_control_coverage(bom)
    residual_score = round(
        exposure["score"] * (1.0 - coverage["score"]),
        3,
    )

    return {
        "server": bom.server_name,
        "exposure": exposure,
        "control_coverage": coverage,
        "residual_risk": {
            "score": residual_score,
            "formula": "exposure.score * (1 - control_coverage.score)",
        },
    }


def _score_exposure(bom: SemanticMCPBOM) -> dict[str, Any]:
    source_tools = [tool for tool in bom.tools if "source" in tool.roles]
    transformer_tools = [tool for tool in bom.tools if "transformer" in tool.roles]
    sink_tools = [tool for tool in bom.tools if "sink" in tool.roles]
    upstream_tools = {
        tool.name: tool
        for tool in [*source_tools, *transformer_tools]
    }
    high_risk_param_count = sum(len(tool.high_risk_params) for tool in bom.tools)
    cross_boundary_paths = len(upstream_tools) * len(sink_tools)

    role_score = sum(
        EXPOSURE_WEIGHTS.get(role, 0)
        for tool in bom.tools
        for role in tool.roles
    )
    high_risk_param_score = (
        EXPOSURE_WEIGHTS["high_risk_param"] * high_risk_param_count
    )
    cross_boundary_score = (
        EXPOSURE_WEIGHTS["cross_boundary_path"] * cross_boundary_paths
    )
    score = role_score + high_risk_param_score + cross_boundary_score

    return {
        "score": score,
        "role_score": role_score,
        "high_risk_param_score": high_risk_param_score,
        "cross_boundary_score": cross_boundary_score,
        "source_tools": len(source_tools),
        "transformer_tools": len(transformer_tools),
        "sink_tools": len(sink_tools),
        "high_risk_params": high_risk_param_count,
        "cross_boundary_paths": cross_boundary_paths,
        "tool_scores": [
            {
                "tool": tool.name,
                "roles": tool.roles,
                "high_risk_params": tool.high_risk_params,
                "score": (
                    sum(EXPOSURE_WEIGHTS.get(role, 0) for role in tool.roles)
                    + EXPOSURE_WEIGHTS["high_risk_param"] * len(tool.high_risk_params)
                ),
            }
            for tool in bom.tools
        ],
    }


def _score_control_coverage(bom: SemanticMCPBOM) -> dict[str, Any]:
    high_risk_tools = [tool for tool in bom.tools if tool.high_risk_params]
    high_risk_params = [
        (tool, param)
        for tool in bom.tools
        for param in tool.high_risk_params
    ]
    sink_high_risk_params = [
        (tool, param)
        for tool, param in high_risk_params
        if "sink" in tool.roles
    ]
    security_relevant_tools = [
        tool for tool in bom.tools
        if tool.roles or tool.high_risk_params
    ]

    schema_constraint = _ratio(
        sum(
            1
            for tool, param in high_risk_params
            if _param_has_schema_constraint(tool, param)
        ),
        len(high_risk_params),
    )
    validation = _ratio(
        sum(1 for tool in high_risk_tools if _has_validation(tool)),
        len(high_risk_tools),
    )
    allowlist = _ratio(
        sum(
            1
            for tool, param in (sink_high_risk_params or high_risk_params)
            if _param_has_allowlist(tool, param)
        ),
        len(sink_high_risk_params or high_risk_params),
    )
    audit = _ratio(
        sum(1 for tool in bom.tools if tool.has_audit_support),
        len(bom.tools),
    )
    policy_hook = _ratio(
        sum(1 for tool in security_relevant_tools if _has_safety_policy(tool)),
        len(security_relevant_tools),
    )

    components = {
        "schema_constraint": schema_constraint,
        "validation": validation,
        "allowlist": allowlist,
        "audit": audit,
        "policy_hook": policy_hook,
    }
    score = sum(
        components[name] * weight
        for name, weight in CONTROL_COVERAGE_WEIGHTS.items()
    )

    return {
        "score": round(score, 3),
        "components": {
            name: round(value, 3)
            for name, value in components.items()
        },
        "weights": CONTROL_COVERAGE_WEIGHTS,
        "opportunities": {
            "high_risk_params": len(high_risk_params),
            "high_risk_tools": len(high_risk_tools),
            "sink_high_risk_params": len(sink_high_risk_params),
            "tools": len(bom.tools),
            "security_relevant_tools": len(security_relevant_tools),
        },
    }


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return numerator / denominator


def _param_has_schema_constraint(tool: SemanticTool, param: str) -> bool:
    schema = tool.input_schema.get("properties", {}).get(param, {})
    return any(key in schema for key in SCHEMA_CONSTRAINT_KEYS)


def _has_validation(tool: SemanticTool) -> bool:
    evidence = tool.evidence or {}
    return bool(evidence.get("has_validation", False))


def _param_has_allowlist(tool: SemanticTool, param: str) -> bool:
    schema = tool.input_schema.get("properties", {}).get(param, {})
    evidence = tool.evidence or {}
    return bool(
        schema.get("enum")
        or schema.get("const")
        or evidence.get("has_allowlist", False)
    )


def _has_safety_policy(tool: SemanticTool) -> bool:
    text = " ".join(
        [
            tool.description,
            *tool.instructions,
            str((tool.evidence or {}).get("raw_description", "")),
        ]
    ).lower()
    if any(marker in text for marker in UNSAFE_POLICY_MARKERS):
        return False
    return any(marker in text for marker in SAFETY_POLICY_MARKERS)
