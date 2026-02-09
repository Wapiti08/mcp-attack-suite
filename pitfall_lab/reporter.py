"""
Pitfall Lab Reporter - Generate formatted reports from run analysis.

Supports multiple output formats:
- Markdown (.md)
- HTML (.html)
- JSON (.json)
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .parser import RunAnalysis


def generate_markdown_report(analysis: RunAnalysis, *, verbose: bool = False) -> str:
    """
    Generate a Markdown report from run analysis.
    
    Args:
        analysis: Parsed run analysis
        verbose: Include detailed tool call information
    
    Returns:
        Markdown-formatted report string
    """
    lines = [
        f"# Run Report: {analysis.run_id}",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        f"- **Challenge:** {analysis.challenge_id}",
        f"- **Attack Type:** {analysis.attack_type}",
        f"- **Submission:** `{analysis.submission_path}`",
        f"- **Result:** {'✓ SUCCESS' if analysis.success else '✗ FAILED'}",
        "",
        "## Validation Results",
        "",
        f"- **Objective:** {analysis.validation.objective_type}",
        f"- **Attacker Identity:** {analysis.validation.attacker_identity}",
        f"- **Objective Hit:** {analysis.validation.hit}",
    ]
    
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


def generate_json_report(analysis: RunAnalysis) -> str:
    """
    Generate a JSON report from run analysis.
    
    Args:
        analysis: Parsed run analysis
    
    Returns:
        JSON-formatted report string
    """
    report = {
        "run_id": analysis.run_id,
        "challenge_id": analysis.challenge_id,
        "attack_type": analysis.attack_type,
        "submission_path": analysis.submission_path,
        "success": analysis.success,
        "generated_at": datetime.now().isoformat(),
        "validation": {
            "objective_type": analysis.validation.objective_type,
            "attacker_identity": analysis.validation.attacker_identity,
            "hit": analysis.validation.hit,
            "evidence": analysis.validation.evidence,
            "error": analysis.validation.error,
        },
        "statistics": {
            "total_turns": analysis.total_turns,
            "total_tool_calls": analysis.total_tool_calls,
            "failed_tool_calls": len(analysis.get_failed_tool_calls()),
        },
        "servers": analysis.servers,
        "agent_final_output": analysis.agent_final_output,
        "tool_calls": [
            {
                "turn": tc.turn,
                "server": tc.server,
                "tool_name": tc.tool_name,
                "exposed_name": tc.exposed_name,
                "args": tc.args,
                "result": tc.result,
                "success": tc.success,
                "timestamp": tc.timestamp,
            }
            for tc in analysis.all_tool_calls
        ],
        "turns": [
            {
                "turn_number": turn.turn_number,
                "timestamp": turn.timestamp,
                "tool_calls_count": len(turn.tool_calls),
            }
            for turn in analysis.turns
        ],
    }
    
    return json.dumps(report, indent=2, ensure_ascii=False)


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
        format: Output format ('markdown', 'html', 'json')
        output_path: Optional output file path (auto-generated if None)
        verbose: Include detailed information (for markdown/html)
    
    Returns:
        Path to generated report file
    
    Raises:
        ValueError: If format is not supported
    """
    # Generate report content
    if format == "markdown":
        content = generate_markdown_report(analysis, verbose=verbose)
        ext = ".md"
    elif format == "html":
        content = generate_html_report(analysis, verbose=verbose)
        ext = ".html"
    elif format == "json":
        content = generate_json_report(analysis)
        ext = ".json"
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'markdown', 'html', or 'json'.")
    
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
