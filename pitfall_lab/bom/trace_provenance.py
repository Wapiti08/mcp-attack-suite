from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from pitfall_lab.bom.semantic_bom import SemanticMCPBOM


@dataclass
class TraceStep:
    turn: int
    tool: str
    roles: list[str]
    args: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProvenanceFinding:
    finding_type: str
    severity: str
    path: list[str]
    evidence: str
    trace_steps: list[TraceStep]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "path": self.path,
            "evidence": self.evidence,
            "trace_steps": [step.to_dict() for step in self.trace_steps],
        }


def analyze_trace_provenance(
    trace_path: str | Path,
    bom: SemanticMCPBOM,
) -> list[ProvenanceFinding]:
    role_by_tool = {
        tool.name: tool.roles
        for tool in bom.tools
    }

    steps: list[TraceStep] = []

    with Path(trace_path).open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            event = json.loads(line)
            if event.get("event") != "llm.tool_call":
                continue

            tool_name = event.get("name", "")
            roles = role_by_tool.get(tool_name, [])

            if not roles:
                continue

            steps.append(
                TraceStep(
                    turn=int(event.get("turn", 0)),
                    tool=tool_name,
                    roles=roles,
                    args=event.get("args") or {},
                )
            )

    return detect_source_to_sink_paths(steps)


def detect_source_to_sink_paths(steps: list[TraceStep]) -> list[ProvenanceFinding]:
    findings: list[ProvenanceFinding] = []

    seen_source = False
    seen_transformer = False
    path: list[TraceStep] = []

    for step in steps:
        if "source" in step.roles:
            seen_source = True
            path.append(step)
            continue

        if seen_source and "transformer" in step.roles:
            seen_transformer = True
            path.append(step)
            continue

        if seen_source and "sink" in step.roles:
            path.append(step)

            if seen_transformer:
                finding_type = "P4_image_or_transformer_to_sink"
                evidence = "Trace contains source -> transformer -> sink tool-call chain."
            else:
                finding_type = "P3_source_to_sink"
                evidence = "Trace contains source -> sink tool-call chain."

            findings.append(
                ProvenanceFinding(
                    finding_type=finding_type,
                    severity="HIGH",
                    path=[item.tool for item in path],
                    evidence=evidence,
                    trace_steps=list(path),
                )
            )

            path = []
            seen_source = False
            seen_transformer = False

    return findings
