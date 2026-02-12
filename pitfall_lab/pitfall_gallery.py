'''
Pitfall Gallery Generator

Automatically generates attack case study reports.
Each pitfall includes evidence from actual runs, attack paths, and mitigations.

'''
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .parser import RunAnalysis
from .taxonomy import Taxonomy


@dataclass
class PitfallReport:
    '''
    Analysis report for a specific pitfall type.
    '''
    pitfall_id: str
    pitfall_name: str
    description: str
    severity: str

    common_pitfalls: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    
    total_runs: int = 0
    affected_runs: int = 0
    success_rate: float = 0.0
    
    evidence_examples: list[dict[str, Any]] = field(default_factory=list)
    typical_attack_paths: list[list[str]] = field(default_factory=list)
    affected_scenarios: list[str] = field(default_factory=list)
    
    metrics: dict[str, Any] = field(default_factory=dict)


def find_runs_for_pitfall(
    pitfall_id: str,
    all_runs: list[RunAnalysis],
    taxonomy: Taxonomy
) -> list[RunAnalysis]:
    """Find all runs related to a specific pitfall."""
    relevant_runs = []

    for scenario in taxonomy.get_all_scenarios():
        scenario_coverage = taxonomy.get_scenario_coverage(scenario.scenario_id)

        if pitfall_id not in scenario_coverage.primary_threats:
            continue

        for attack_name, threats in scenario_coverage.attack_threats.items(): 
            if pitfall_id in threats: 
                for run in all_runs: 
                    if (run.scenario_id == scenario.scenario_id and 
                        run.attack_name == attack_name): 
                        relevant_runs.append(run) 
                        return relevant_runs
    
    return relevant_runs    

def extract_evidence_examples(
    runs: list[RunAnalysis],
    pitfall_id: str,
    max_examples: int = 3
    ) -> list[dict[str, Any]]:
    """Extract typical evidence cases from runs."""
    examples = []
    successful_runs = [r for r in runs if r.success]

    for run in successful_runs[:max_examples]:
        example = {
            "run_id": run.run_id,
            "scenario": run.challenge_id,
            "attack": run.attack_type,
            "success": run.success,
            "key_tool_calls": [],
            "validation": {
                "objective": run.validation.objective_type,
                "hit": run.validation.hit,
                "evidence": run.validation.evidence
            }
        }

        # Extract key tool calls based on pitfall type
        for tc in run.all_tool_calls:
            if "send" in tc.tool_name.lower() or "message" in tc.tool_name.lower():
                example["key_tool_calls"].append({
                    "tool": tc.tool_name,
                    "args": tc.args,
                    "success": tc.success
                })
        
        examples.append(example)
    
    return examples


def extract_attack_path(run: RunAnalysis) -> list[str]:
    """Reconstruct attack path from run."""
    path = []
    sorted_calls = sorted(run.all_tool_calls, key=lambda tc: tc.turn)

    for i, tc in enumerate(sorted_calls, 1):
        if "read" in tc.tool_name.lower() or "get" in tc.tool_name.lower():
            step = f"{i}. Agent retrieves data via {tc.tool_name}()"
        elif "send" in tc.tool_name.lower():
            recipient = tc.args.get("to") or tc.args.get("channel")
            step = f"{i}. Agent sends data via {tc.tool_name}(recipient={recipient})"
        else:
            step = f"{i}. Agent calls {tc.tool_name}()"
        
        path.append(step)
    
    if run.validation.hit:
        path.append(f"{len(path)+1}. Validation detects: {run.validation.objective_type}")
    
    return path

def generate_pitfall_report(
    pitfall_id: str,
    all_runs: list[RunAnalysis],
    taxonomy: Taxonomy
    ) -> PitfallReport:
    """Generate complete report for a specific pitfall."""

    category = taxonomy.get_category(pitfall_id)
    if not category:
        raise ValueError(f"Unknown pitfall ID: {pitfall_id}")
    
    relevant_runs = find_runs_for_pitfall(pitfall_id, all_runs, taxonomy)

    total_runs = len(relevant_runs)
    successful_attacks = [r for r in relevant_runs if r.success]
    success_rate = len(successful_attacks) / total_runs if total_runs > 0 else 0.0
    
    evidence_examples = extract_evidence_examples(relevant_runs, pitfall_id, max_examples=3)

    typical_paths = []
    for run in successful_attacks[:2]:
        path = extract_attack_path(run)
        typical_paths.append(path)
    
    affected_scenarios = list(set(r.challenge_id for r in relevant_runs))

    # multimodal-specific metrics
    metrics = {}
    if pitfall_id == "multimodal_injection":
        from .evaluator import evaluate_multimodal_impact

        for scenario_id in affected_scenarios:
            scenario_runs = [r for r in relevant_runs if r.challenge_id == scenario_id]
            mm_metrics = evaluate_multimodal_impact(scenario_runs, scenario_id)

            if mm_metrics.has_multimodal_runs:
                metrics[scenario_id] = {
                    "text_only_asr": mm_metrics.text_only_asr,
                    "multimodal_asr": mm_metrics.multimodal_asr,
                    "incremental_risk": mm_metrics.incremental_risk
                }

    report = PitfallReport(
        pitfall_id=pitfall_id,
        pitfall_name=category.name,
        description=category.description,
        severity=category.severity,
        common_pitfalls=category.common_pitfalls,
        mitigations=category.mitigations,
        total_runs=total_runs,
        affected_runs=len(successful_attacks),
        success_rate=success_rate,
        evidence_examples=evidence_examples,
        typical_attack_paths=typical_paths,
        affected_scenarios=affected_scenarios,
        metrics=metrics
    )
    
    return report


def format_pitfall_report_markdown(report: PitfallReport) -> str:
    """
    format pitfallreport as markdown
    """
    lines = []

    lines.append(f"# Pitfall: {report.pitfall_name}")
    lines.append("")

    meta = [
        f"**Severity:** {report.severity.capitalize()}",
        f"**Affected Scenarios:** {', '.join(report.affected_scenarios)}",
    ]

    lines.append(" | ".join(meta))
    lines.append("")
    
    lines.append("## Description")
    lines.append("")
    lines.append(report.description)
    lines.append("")

    if report.common_pitfalls:
        lines.append("## Common Developer Mistakes")
        lines.append("")
        for pitfall in report.common_pitfalls:
            lines.append(f"- {pitfall}")
        lines.append("")
    
    lines.append("## Evidence Summary")
    lines.append("")
    stats = [
        f"**Total Runs:** {report.total_runs}",
        f"**Attacks Successful:** {report.affected_runs}",
        f"**Success Rate:** {report.success_rate:.1%}"
    ]
    lines.append(" | ".join(stats))
    lines.append("")

    if report.evidence_examples:
        lines.append("## Representative Evidence")
        lines.append("")
        
        for i, example in enumerate(report.evidence_examples, 1):
            lines.append(f"### Example {i}: {example['scenario']} + {example['attack']}")
            lines.append("")
            lines.append(f"**Run ID:** `{example['run_id']}`")
            lines.append(f"**Outcome:** {'✓ Attack succeeded' if example['success'] else '✗ Attack failed'}")
            lines.append("")
            
            if example.get("key_tool_calls"):
                lines.append("**Key Tool Calls:**")
                lines.append("```json")
                lines.append(json.dumps(example["key_tool_calls"], indent=2))
                lines.append("```")
                lines.append("")


    if report.typical_attack_paths:
        lines.append("## Typical Attack Paths")
        lines.append("")
        
        for i, path in enumerate(report.typical_attack_paths, 1):
            lines.append(f"### Path {i}")
            lines.append("")
            for step in path:
                lines.append(step)
            lines.append("")
    
    if report.metrics:
        lines.append("## Multimodal Impact Analysis")
        lines.append("")
        
        for scenario, metrics in report.metrics.items():
            lines.append(f"### {scenario}")
            lines.append("")
            lines.append(f"- Text-only ASR: {metrics['text_only_asr']:.1%}")
            lines.append(f"- Multimodal ASR: {metrics['multimodal_asr']:.1%}")
            lines.append(f"- **Incremental Risk:** {metrics['incremental_risk']:+.1%}")
            lines.append("")

    if report.mitigations:
        lines.append("## Mitigation Strategies")
        lines.append("")
        for mitigation in report.mitigations:
            lines.append(f"- {mitigation}")
        lines.append("")
    
    lines.append("---")
    lines.append(f"*Report generated from {report.total_runs} run(s)*")
    
    return "\n".join(lines)


def generate_pitfall_gallery(
    all_runs: list[RunAnalysis],
    taxonomy: Taxonomy,
    output_dir: Path | None = None
) -> dict[str, PitfallReport]:
    """
    Generate complete Pitfall Gallery.
    
    Creates a report for each threat category in the taxonomy.
    """
    gallery = {}

    for category in taxonomy.get_all_categories():
        print(f"Generating report for {category.id}...")

        try:
            report = generate_pitfall_report(category.id, all_runs, taxonomy)
            gallery[category.id] = report

            if output_dir:
                output_dir.mkdir(parents=True, exist_ok=True)

                md_path = output_dir / f"{category.id}.md"
                md_content = format_pitfall_report_markdown(report)

                md_path.write_text(md_content, encoding="utf-8")

                json_path = output_dir / f"{category.id}.json"
                json_data = {
                    "pitfall_id": report.pitfall_id,
                    "name": report.pitfall_name,
                    "severity": report.severity,
                    "stats": {
                        "total_runs": report.total_runs,
                        "success_rate": report.success_rate
                    },
                    "evidence": report.evidence_examples,
                    "mitigations": report.mitigations
                }
                json_path.write_text(
                    json.dumps(json_data, indent=2, ensure_ascii=False),
                    encoding="utf-8"
                )
                
                print(f"  ✓ Saved to {md_path}")
        
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            continue
    
    if output_dir:
        index_path = output_dir / "INDEX.md"
        index_content = generate_gallery_index(gallery)
        index_path.write_text(index_content, encoding="utf-8")
        print(f"\n✓ Gallery index: {index_path}")
    

def generate_gallery_index(gallery: dict[str, PitfallReport]) -> str:
    """Generate Gallery index page."""
    lines = [
        "# Pitfall Gallery - Attack Case Studies",
        "",
        "Systematic analysis of security pitfalls in MCP deployments.",
        "",
        "## Summary",
        "",
    ]

    total_runs = sum(r.total_runs for r in gallery.values())
    lines.append(f"**Total Pitfalls Analyzed:** {len(gallery)}")
    lines.append(f"**Total Runs Processed:** {total_runs}")
    lines.append("")

    by_severity = {}
    for report in gallery.values():
        by_severity.setdefault(report.severity, []).append(report)
    
    for severity in ["critical", "high", "medium", "low"]:
        if severity in by_severity:
            lines.append(f"### {severity.capitalize()} Severity")
            lines.append("")
            for report in by_severity[severity]:
                lines.append(
                    f"- [{report.pitfall_name}]({report.pitfall_id}.md) "
                    f"({report.affected_runs}/{report.total_runs} successful attacks)"
                )
            lines.append("")
    
    return "\n".join(lines)



