"""
Pitfall Lab CLI - Command-line interface for running and analyzing MCP security tests.

Usage:
    pitfall run --server <path> --challenge <id> --attack <attack>
    pitfall analyze --run-id <id>
    pitfall report --run-id <id> [--verbose]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .runner import run_challenge, get_run_dir, ensure_arena_importable
from .parser import parse_run, summarize_run
from .eval_cli import add_evaluation_commands, cmd_evaluate_scenario, cmd_compare_scenarios


def cmd_run(args: argparse.Namespace) -> int:
    """Execute a challenge run with a submission."""
    try:
        print(f"Running challenge: {args.challenge}")
        print(f"Attack: {args.attack}")
        print(f"Submission: {args.submission}")
        print()
        
        result = run_challenge(
            challenge_id=args.challenge,
            attack=args.attack,
            submission=args.submission,
            out_dir=Path(args.out) if args.out else None,
        )
        
        print()
        print("=" * 60)
        print("RUN COMPLETE")
        print("=" * 60)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
        # Auto-generate summary if requested
        if not args.no_summary:
            print()
            print("=" * 60)
            print("SUMMARY")
            print("=" * 60)
            run_id = result.get("run_id")
            if run_id:
                try:
                    run_dir = get_run_dir(run_id)
                    analysis = parse_run(run_dir)
                    print(summarize_run(analysis, verbose=args.verbose))
                except Exception as e:
                    print(f"Warning: Could not generate summary: {e}")
        
        return 0 if result.get("ok") else 1
        
    except Exception as e:
        print(f"Error running challenge: {e}", file=sys.stderr)
        if args.debug:
            raise
        return 2


def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyze an existing run."""
    try:
        ensure_arena_importable()
        run_dir = get_run_dir(args.run_id)
        
        print(f"Analyzing run: {args.run_id}")
        print(f"Run directory: {run_dir}")
        print()
        
        analysis = parse_run(run_dir)
        
        print(summarize_run(analysis, verbose=args.verbose))
        
        # Export structured data if requested
        if args.export:
            export_path = Path(args.export)
            export_data = {
                "run_id": analysis.run_id,
                "challenge": analysis.challenge_id,
                "attack": analysis.attack_type,
                "success": analysis.success,
                "validation": {
                    "objective": analysis.validation.objective_type,
                    "attacker": analysis.validation.attacker_identity,
                    "hit": analysis.validation.hit,
                    "evidence": analysis.validation.evidence,
                },
                "stats": {
                    "total_turns": analysis.total_turns,
                    "total_tool_calls": analysis.total_tool_calls,
                    "failed_calls": len(analysis.get_failed_tool_calls()),
                },
                "tool_calls": [
                    {
                        "turn": tc.turn,
                        "server": tc.server,
                        "tool": tc.tool_name,
                        "exposed_as": tc.exposed_name,
                        "success": tc.success,
                        "args": tc.args,
                        "result": tc.result,
                    }
                    for tc in analysis.all_tool_calls
                ],
            }
            export_path.write_text(json.dumps(export_data, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"\nExported analysis to: {export_path}")
        
        return 0
        
    except Exception as e:
        print(f"Error analyzing run: {e}", file=sys.stderr)
        if args.debug:
            raise
        return 2


def cmd_report(args: argparse.Namespace) -> int:
    """Generate a detailed report from a run."""
    try:
        ensure_arena_importable()
        run_dir = get_run_dir(args.run_id)
        
        analysis = parse_run(run_dir)
        
        # Import report generator
        from .reporter import generate_report
        
        report_path = generate_report(
            analysis,
            format=args.format,
            output_path=args.output,
            verbose=True,
        )
        
        print(f"✓ Report generated: {report_path}")
        print(f"  Format: {args.format}")
        print(f"  Run ID: {analysis.run_id}")
        print(f"  Challenge: {analysis.challenge_id}")
        print(f"  Success: {analysis.success}")
        
        return 0
        
    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)
        if args.debug:
            raise
        return 2


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="pitfall",
        description="Pitfall Lab - MCP Security Testing Framework",
    )
    parser.add_argument("--debug", action="store_true", help="Show full stack traces on error")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run a challenge with a submission")
    run_parser.add_argument("--challenge", required=True, help="Challenge ID (e.g., emailsystem, cryptosystem)")
    run_parser.add_argument("--attack", required=True, help="Attack config name")
    run_parser.add_argument(
        "--submission",
        required=True,
        help="Path to submission artifact or raw injection string (for tool_poisoning)",
    )
    run_parser.add_argument("--out", help="Output directory for run artifacts (default: environment/runs)")
    run_parser.add_argument("--no-summary", action="store_true", help="Skip auto-generating summary")
    run_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed tool call information")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze an existing run")
    analyze_parser.add_argument("--run-id", required=True, help="Run ID to analyze")
    analyze_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed analysis")
    analyze_parser.add_argument("--export", help="Export structured analysis to JSON file")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate a detailed report")
    report_parser.add_argument("--run-id", required=True, help="Run ID to report on")
    report_parser.add_argument("--output", "-o", help="Output path for report (default: auto-generated)")
    report_parser.add_argument(
        "--format",
        choices=["markdown", "html", "json"],
        default="markdown",
        help="Report format",
    )
    
    # Add scenario evaluation commands
    add_evaluation_commands(subparsers)
    
    args = parser.parse_args(argv)
    
    if args.command == "run":
        return cmd_run(args)
    elif args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "report":
        return cmd_report(args)
    elif args.command == "eval-scenario":
        return cmd_evaluate_scenario(args)
    elif args.command == "compare-scenarios":
        return cmd_compare_scenarios(args)
    
    return 1


if __name__ == "__main__":
    sys.exit(main())
