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

