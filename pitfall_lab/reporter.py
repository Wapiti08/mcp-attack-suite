"""
Pitfall Lab Reporter - Generate formatted reports from run analysis.

Supports multiple output formats:
- Markdown (.md)
- JSON (.json)
"""
from __future__ import annotations
from dataclasses import dataclass, field
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .parser import RunAnalysis
from .evidence import analyze_evidence_vs_self_report, EvidenceVsSelfReport

def generate_markdown_report(analysis: RunAnalysis, *, verbose: bool = False) -> str:
    """
    Generate a Markdown report from run analysis.
    
    Args:
        analysis: Parsed run analysis
        verbose: Include detailed tool call information
    
    Returns:
        Markdown-formatted report string
    """
    lines = []
    
    # Title
    lines.append(f"# Run Report: {analysis.run_id}")
    lines.append("")
    
    # Metadata
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Challenge:** {analysis.challenge_id}")
    lines.append(f"- **Attack:** {analysis.attack_type}")
    lines.append(f"- **Success:** {'✓ Yes' if analysis.success else '✗ No'}")
    lines.append(f"- **Total Turns:** {analysis.total_turns}")
    lines.append(f"- **Total Tool Calls:** {len(analysis.all_tool_calls)}")
    lines.append("")
    
    # Evidence-Based Validation Section
    evidence = analyze_evidence_vs_self_report(analysis)
    lines.append(format_evidence_section(evidence))
    lines.append("")
    
    # Validation Results
    lines.append("## Validation Results")
    lines.append("")
    lines.append(f"- **Objective Type:** `{analysis.validation.objective_type}`")
    lines.append(f"- **Hit:** {analysis.validation.hit}")
    
    if analysis.validation.attacker_identity:
        lines.append(f"- **Attacker Identity:** `{analysis.validation.attacker_identity}`")
    
    if analysis.validation.error:
        lines.append(f"- **Error:** {analysis.validation.error}")
    
    if analysis.validation.evidence:
        lines.extend([
            "",
            "**Evidence:**",
            "```json",
            json.dumps(analysis.validation.evidence, indent=2),
            "```",
        ])
    
    lines.extend([
        "",
        "## Execution Statistics",
        "",
        f"- **Total Turns:** {analysis.total_turns}",
        f"- **Total Tool Calls:** {analysis.total_tool_calls}",
        f"- **Failed Tool Calls:** {len(analysis.get_failed_tool_calls())}",
    ])
    
    # MCP Servers
    lines.extend([
        "",
        "## MCP Servers",
        "",
    ])
    for server in analysis.servers:
        lines.append(f"- **{server['name']}:** {server['url']}")
        lines.append(f"  - Module: `{server.get('module', 'N/A')}`")
    
    # Agent output
    if analysis.agent_final_output:
        lines.extend([
            "",
            "## Agent Final Output",
            "",
            "```",
            analysis.agent_final_output,
            "```",
        ])
    
    # Tool calls details
    if verbose and analysis.all_tool_calls:
        lines.extend([
            "",
            "## Tool Calls Detail",
            "",
        ])
        
        for i, tc in enumerate(analysis.all_tool_calls, 1):
            status = "✓" if tc.success else "✗"
            lines.extend([
                f"### {i}. {status} {tc.exposed_name}",
                "",
                f"- **Turn:** {tc.turn}",
                f"- **Server:** {tc.server}",
                f"- **Tool:** {tc.tool_name}",
                f"- **Timestamp:** {tc.timestamp or 'N/A'}",
                "",
                "**Arguments:**",
                "```json",
                json.dumps(tc.args, indent=2),
                "```",
                "",
                "**Result:**",
                "```json",
                json.dumps(tc.result, indent=2),
                "```",
                "",
            ])
    
    # Turn-by-turn breakdown
    if verbose and analysis.turns:
        lines.extend([
            "",
            "## Turn-by-Turn Breakdown",
            "",
        ])
        
        for turn in analysis.turns:
            lines.extend([
                f"### Turn {turn.turn_number}",
                "",
            ])
            
            if turn.tool_calls:
                lines.append("**Actions:**")
                for tc in turn.tool_calls:
                    status = "✓" if tc.success else "✗"
                    lines.append(f"- {status} `{tc.server}.{tc.tool_name}()`")
                lines.append("")
    
    return "\n".join(lines)

def format_evidence_section(evidence: EvidenceVsSelfReport) -> str:
    """
    Format evidence vs self-report section for Markdown report.

    Args:
    evidence: Evidence analysis results

    Returns:
        Markdown formatted string
    """
    lines = []

    # Header
    lines.append("## Evidence-Based Validation")
    lines.append("")
    lines.append("*(Protocol-level evidence vs agent self-report)*")
    lines.append("")

    # No divergence case
    if not evidence.has_divergence:
        lines.append("✅ **No divergence detected**")
        lines.append("")
        lines.append("Agent's self-report aligns with protocol-level evidence.")
        return "\n".join(lines)

    # Divergence detected
    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "none": "⚪"
    }

    emoji = severity_emoji.get(evidence.divergence_severity, "⚠️")

    lines.append(f"{emoji} **DIVERGENCE DETECTED** (Severity: {evidence.divergence_severity.upper()})")
    lines.append("")

    # Divergence types
    if evidence.divergence_types:
        types_str = ", ".join([t.replace("_", " ").title() for t in evidence.divergence_types])
        lines.append(f"**Types:** {types_str}")
        lines.append("")

    # Agent's claim
    if evidence.agent_claim:
        lines.append("### Agent Claimed:")
        lines.append("")
        # Truncate long outputs
        claim = evidence.agent_claim[:300]
        if len(evidence.agent_claim) > 300:
            claim += "..."
        lines.append(f"> {claim}")
        lines.append("")

    # Protocol evidence
    lines.append("### Protocol Evidence Shows:")
    lines.append("")
    lines.append(f"- **Validation Result:** {'✓ Objective hit' if evidence.actual_validation_result else '✗ Objective not hit'}")
    lines.append(f"- **Tool Calls Executed:** {evidence.actual_tool_calls_count}")

    if evidence.actual_sensitive_tool_calls:
        lines.append(f"- **Sensitive Operations:** {', '.join(evidence.actual_sensitive_tool_calls[:5])}")

    lines.append("")

    # Issues
    if evidence.issues:
        lines.append("### Issues Identified:")
        lines.append("")
        
        for i, issue in enumerate(evidence.issues, 1):
            # Issues might be multi-line
            lines.append(f"**{i}. {issue.split(':')[0] if ':' in issue else 'Issue'}**")
            lines.append("")
            # Indent issue details
            issue_lines = issue.split('\n')
            for line in issue_lines:
                if line.strip():
                    lines.append(f"   {line}")
            lines.append("")

    # Evidence summary
    lines.append("### Evidence Summary:")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(evidence.evidence_summary, indent=2))
    lines.append("```")
    lines.append("")

    # Developer guidance
    if evidence.divergence_severity in ["critical", "high"]:
        lines.append("### ⚠️ Action Required:")
        lines.append("")
        lines.append("This divergence indicates a **trust calibration problem**: developers ")
        lines.append("relying on agent self-report would have incorrect understanding of what happened.")
        lines.append("")
        lines.append("**Recommendations:**")
        lines.append("- Review agent planning logic")
        lines.append("- Implement server-side validation for sensitive operations")
        lines.append("- Add explicit approval gates for high-risk actions")
        lines.append("")

    return "\n".join(lines)


def generate_json_report(analysis: RunAnalysis, *, verbose: bool = False) -> dict[str, Any]:
    """
    Generate a JSON report from run analysis.
    
    Args:
        analysis: Parsed run analysis
    
    Returns:
        JSON-formatted report string
    """
    # analyze evidence
    evidence = analyze_evidence_vs_self_report(analysis)

    report = {
        "run_id": analysis.run_id,
        "challenge_id": analysis.challenge_id,
        "attack_type": analysis.attack_type,
        "success": analysis.success,
        "total_turns": analysis.total_turns,
        
        # Evidence analysis
        "evidence_analysis": {
            "has_divergence": evidence.has_divergence,
            "divergence_types": evidence.divergence_types,
            "divergence_severity": evidence.divergence_severity,
            "issues_count": len(evidence.issues),
            "issues": evidence.issues,
            "agent_claim": evidence.agent_claim,
            "actual_validation_result": evidence.actual_validation_result,
            "evidence_summary": evidence.evidence_summary
        },
        
        "validation": {
            "objective_type": analysis.validation.objective_type,
            "hit": analysis.validation.hit,
            "attacker_identity": analysis.validation.attacker_identity,
            "error": analysis.validation.error,
            "evidence": analysis.validation.evidence
        },
        
        "statistics": {
            "total_tool_calls": len(analysis.all_tool_calls),
            "successful_tool_calls": len([tc for tc in analysis.all_tool_calls if tc.success]),
            "unique_tools": list({tc.tool_name for tc in analysis.all_tool_calls})
        }
    }
    
    # Optional: detailed tool calls
    if verbose:
        report["tool_calls"] = [
            {
                "turn": tc.turn,
                "server": tc.server,
                "tool": tc.tool_name,
                "args": tc.args,
                "result": tc.result,
                "success": tc.success
            }
            for tc in analysis.all_tool_calls
        ]
    
    if analysis.agent_final_output:
        report["agent_output"] = analysis.agent_final_output
    
    return report

def generate_report(
    analysis: RunAnalysis,
    *,
    format: str = "markdown",
    output_path: Path | str | None = None,
    verbose: bool = False,
) -> Path:
    """
    Generate a report from run analysis.
    
    Args:
        analysis: Parsed run analysis
        format: Output format ('markdown', 'json')
        output_path: Optional output file path (auto-generated if None)
        verbose: Include detailed information (for markdown)
    
    Returns:
        Path to generated report file
    
    Raises:
        ValueError: If format is not supported
    """
    # Generate report content
    if format == "markdown":
        content = generate_markdown_report(analysis, verbose=verbose)
        ext = ".md"
    elif format == "json":
        report_dict = generate_json_report(analysis)
        content = json.dumps(report_dict, indent=2, ensure_ascii=False)
        ext = ".json"
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'markdown', or 'json'.")
    
    # Determine output path
    if output_path is None:
        output_path = Path(f"report_{analysis.run_id}{ext}")
    else:
        output_path = Path(output_path)
        # Ensure correct extension
        if output_path.suffix != ext:
            output_path = output_path.with_suffix(ext)
    
    # Write report
    output_path.write_text(content, encoding="utf-8")
    
    return output_path