"""
Scenario evaluation CLI extensions for pitfall_lab.

Adds commands for evaluating benchmark quality.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluator import (
    evaluate_scenario_from_spec,
    evaluate_scenario_from_runs,
    compare_scenarios,
)
from .parser import parse_run
from .runner import ensure_arena_importable


def cmd_evaluate_scenario(args: argparse.Namespace) -> int:
    """Evaluate a single scenario's quality."""
    try:
        ensure_arena_importable()
        from environment.arena.runner.run import env_root
        
        # Find spec.json
        env_path = env_root()
        challenges_dir = env_path / "arena" / "challenges"
        spec_path = challenges_dir / args.challenge / "spec.json"
        
        if not spec_path.exists():
            print(f"Error: Spec not found at {spec_path}", file=sys.stderr)
            return 1
        
        print(f"Evaluating scenario: {args.challenge}")
        print(f"Spec: {spec_path}")
        print()
        
        # Basic evaluation from spec
        evaluation = evaluate_scenario_from_spec(spec_path)
        
        # If runs provided, enhance with empirical data
        if args.runs_dir:
            runs_dir = Path(args.runs_dir)
            runs = []
            
            for run_path in runs_dir.glob("*/report.json"):
                try:
                    analysis = parse_run(run_path.parent)
                    if analysis.challenge_id == args.challenge:
                        runs.append(analysis)
                except Exception as e:
                    print(f"Warning: Failed to parse {run_path}: {e}")
            
            if runs:
                print(f"Found {len(runs)} historical runs for this challenge")
                ground_truth = None
                if args.ground_truth:
                    with open(args.ground_truth, "r") as f:
                        ground_truth = json.load(f)
                
                evaluation = evaluate_scenario_from_runs(
                    spec_path,
                    runs,
                    ground_truth=ground_truth,
                )
        
        # Display results
        print("=" * 60)
        print("SCENARIO EVALUATION REPORT")
        print("=" * 60)
        print(f"\nChallenge: {evaluation.challenge_id}")
        print(f"Overall Quality Score: {evaluation.overall_quality_score:.2f}/1.00")
        print()
        
        print("Attack Surface:")
        print(f"  Total tools: {evaluation.attack_surface.total_tools}")
        print(f"  Sensitive tools: {evaluation.attack_surface.sensitive_tools}")
        print(f"  Score: {evaluation.attack_surface.attack_surface_score:.2f}")
        print()
        
        print("Difficulty:")
        print(f"  Multi-step required: {evaluation.difficulty.requires_multi_step}")
        if evaluation.difficulty.avg_turns_to_success:
            print(f"  Avg turns to success: {evaluation.difficulty.avg_turns_to_success:.1f}")
        if evaluation.difficulty.success_rate is not None:
            print(f"  Success rate: {evaluation.difficulty.success_rate:.1%}")
        print(f"  Score: {evaluation.difficulty.difficulty_score:.2f}")
        print()
        
        print("Coverage:")
        print(f"  Tested threats: {', '.join(evaluation.coverage.tested_threats)}")
        print(f"  Score: {evaluation.coverage.coverage_score:.2f}")
        print()
        
        if evaluation.discriminability.true_positives + evaluation.discriminability.false_positives > 0:
            print("Discriminability:")
            print(f"  Precision: {evaluation.discriminability.precision:.2f}")
            print(f"  Recall: {evaluation.discriminability.recall:.2f}")
            print(f"  F1 Score: {evaluation.discriminability.f1_score:.2f}")
            print()
        
        print("Realism:")
        print(f"  Score: {evaluation.realism.realism_score:.2f}")
        print()
        
        # Export if requested
        if args.export:
            export_path = Path(args.export)
            export_path.write_text(
                json.dumps(evaluation.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            print(f"Exported to: {export_path}")
        
        return 0
        
    except Exception as e:
        print(f"Error evaluating scenario: {e}", file=sys.stderr)
        if args.debug:
            raise
        return 2


def cmd_compare_scenarios(args: argparse.Namespace) -> int:
    """Compare multiple scenarios."""
    try:
        ensure_arena_importable()
        from environment.arena.runner.run import env_root
        
        env_path = env_root()
        challenges_dir = env_path / "arena" / "challenges"
        
        # Get challenges to compare
        if args.challenges:
            challenge_ids = args.challenges.split(",")
        else:
            # Auto-discover all challenges
            challenge_ids = [
                d.name for d in challenges_dir.iterdir()
                if d.is_dir() and (d / "spec.json").exists()
            ]
        
        print(f"Comparing {len(challenge_ids)} scenarios:")
        print(f"  {', '.join(challenge_ids)}")
        print()
        
        # Evaluate each scenario
        evaluations = []
        for challenge_id in challenge_ids:
            spec_path = challenges_dir / challenge_id / "spec.json"
            if not spec_path.exists():
                print(f"Warning: Skipping {challenge_id} (no spec.json)")
                continue
            
            try:
                evaluation = evaluate_scenario_from_spec(spec_path)
                evaluations.append(evaluation)
                print(f"✓ Evaluated {challenge_id}")
            except Exception as e:
                print(f"✗ Failed to evaluate {challenge_id}: {e}")
        
        if not evaluations:
            print("Error: No scenarios successfully evaluated", file=sys.stderr)
            return 1
        
        # Generate comparison
        comparison = compare_scenarios(evaluations)
        
        print()
        print("=" * 60)
        print("SCENARIO COMPARISON REPORT")
        print("=" * 60)
        print()
        
        print(f"Total scenarios: {comparison['summary']['total_scenarios']}")
        print(f"Average quality: {comparison['summary']['avg_quality_score']:.2f}/1.00")
        print()
        
        print("Rankings (by overall quality):")
        for rank in comparison["rankings"]:
            print(f"  {rank['rank']}. {rank['challenge_id']}: {rank['score']:.2f}")
        print()
        
        print("Best in Each Category:")
        for category, challenge in comparison["best_in_category"].items():
            print(f"  {category.capitalize()}: {challenge}")
        print()
        
        # Detailed comparison table
        if args.detailed:
            print("Detailed Comparison:")
            print(f"{'Challenge':<20} {'Overall':<10} {'Coverage':<10} {'Discrim':<10} {'Difficulty':<12} {'Realism':<10}")
            print("-" * 80)
            for item in comparison["detailed_comparison"]:
                print(
                    f"{item['challenge_id']:<20} "
                    f"{item['overall_score']:<10.2f} "
                    f"{item['coverage_score']:<10.2f} "
                    f"{item['discriminability_f1']:<10.2f} "
                    f"{item['difficulty_score']:<12.2f} "
                    f"{item['realism_score']:<10.2f}"
                )
            print()
        
        # Export if requested
        if args.export:
            export_path = Path(args.export)
            export_path.write_text(
                json.dumps(comparison, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            print(f"Exported to: {export_path}")
        
        return 0
        
    except Exception as e:
        print(f"Error comparing scenarios: {e}", file=sys.stderr)
        if args.debug:
            raise
        return 2


def add_evaluation_commands(subparsers) -> None:
    """Add scenario evaluation commands to CLI."""
    
    # Evaluate single scenario
    eval_parser = subparsers.add_parser(
        "eval-scenario",
        help="Evaluate a single scenario's quality as a benchmark"
    )
    eval_parser.add_argument(
        "--challenge",
        required=True,
        help="Challenge ID to evaluate (e.g., emailsystem)"
    )
    eval_parser.add_argument(
        "--runs-dir",
        help="Directory with historical runs (for empirical metrics)"
    )
    eval_parser.add_argument(
        "--ground-truth",
        help="JSON file mapping run_id -> is_malicious (for discriminability)"
    )
    eval_parser.add_argument(
        "--export",
        help="Export evaluation to JSON file"
    )
    
    # Compare scenarios
    compare_parser = subparsers.add_parser(
        "compare-scenarios",
        help="Compare multiple scenarios"
    )
    compare_parser.add_argument(
        "--challenges",
        help="Comma-separated challenge IDs (default: all)"
    )
    compare_parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show detailed comparison table"
    )
    compare_parser.add_argument(
        "--export",
        help="Export comparison to JSON file"
    )
