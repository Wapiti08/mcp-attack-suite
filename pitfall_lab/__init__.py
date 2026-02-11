"""
Pitfall Lab - MCP Security Testing Framework

A testing framework for evaluating Model Context Protocol (MCP) server security.
Maps to the arena challenge infrastructure for automated security testing.
"""

__version__ = "0.3.0" 

# ============================================================================
# Phase 1: Run and Analyze
# ============================================================================

# Runner: Execute challenges
from .runner import run_challenge, get_run_dir

# Parser: Analyze run results
from .parser import (
    parse_run,
    summarize_run,
    RunAnalysis,
    ValidationResult,
    ToolCall
)

# Reporter: Generate reports
from .reporter import generate_report


# ============================================================================
# Phase 2: Scenario Evaluation
# ============================================================================

# Evaluator: Assess benchmark quality
from .evaluator import (
    evaluate_scenario_from_spec,
    evaluate_scenario_from_runs,
    compare_scenarios,
    ScenarioEvaluation
)


# ============================================================================
# Taxonomy: Threat Classification (NEW)
# ============================================================================

# Main functions
from .taxonomy import (
    load_taxonomy,
    get_coverage_report
)

# Advanced: For custom analysis
from .taxonomy import (
    Taxonomy,
    get_scenario_threats
)


# ============================================================================
# Evidence Analysis: Self-Report vs Protocol Evidence (NEW)
# ============================================================================

# Main function
from .evidence import analyze_evidence_vs_self_report

# Result type
from .evidence import EvidenceVsSelfReport


# ============================================================================
# Pitfall Gallery: Attack Case Studies (NEW)
# ============================================================================

# Main functions
from .pitfall_gallery import (
    generate_pitfall_gallery,
    generate_pitfall_report
)

# Result type
from .pitfall_gallery import PitfallReport


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    # Runner
    "run_challenge",
    "get_run_dir",
    
    # Parser
    "parse_run",
    "summarize_run",
    "RunAnalysis",
    "ValidationResult",
    "ToolCall",
    
    # Reporter
    "generate_report",
    
    # Evaluator
    "evaluate_scenario_from_spec",
    "evaluate_scenario_from_runs",
    "compare_scenarios",
    "ScenarioEvaluation",
    
    # Taxonomy (NEW)
    "load_taxonomy",
    "get_coverage_report",
    "Taxonomy",
    "get_scenario_threats",
    
    # Evidence (NEW)
    "analyze_evidence_vs_self_report",
    "EvidenceVsSelfReport",
    
    # Pitfall Gallery (NEW)
    "generate_pitfall_gallery",
    "generate_pitfall_report",
    "PitfallReport",
]