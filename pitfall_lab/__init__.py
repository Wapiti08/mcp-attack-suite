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
from .core.runner import run_challenge, get_run_dir

# Parser: Analyze run results
from .core.parser import (
    parse_run,
    summarize_run,
    RunAnalysis,
    ValidationResult,
    ToolCall
)

# Reporter: Generate reports
from .core.reporter import generate_report


# ============================================================================
# Phase 2: Scenario Evaluation
# ============================================================================

# Evaluator: Assess benchmark quality
from .benchmark.evaluator import (
    evaluate_scenario_from_spec,
    evaluate_scenario_from_runs,
    compare_scenarios,
    ScenarioEvaluation
)


# ============================================================================
# Taxonomy: Threat Classification (NEW)
# ============================================================================

# Main functions
from .benchmark.taxonomy import (
    load_taxonomy,
    get_coverage_report
)

# Advanced: For custom analysis
from .benchmark.taxonomy import (
    Taxonomy,
    get_scenario_threats
)


# ============================================================================
# Evidence Analysis: Self-Report vs Protocol Evidence (NEW)
# ============================================================================

# Main function
from .core.evidence import analyze_evidence_vs_self_report

# Result type
from .core.evidence import EvidenceVsSelfReport


# ============================================================================
# Pitfall Gallery: Attack Case Studies (NEW)
# ============================================================================

# Main functions
from .benchmark.pitfall_gallery import (
    generate_pitfall_gallery,
    generate_pitfall_report
)

# Result type
from .benchmark.pitfall_gallery import PitfallReport


# ============================================================================
# Semantic MCP-BOM: Manifest Construction and Vetting
# ============================================================================

from .bom import (
    BOMFinding,
    SemanticBOMConfig,
    SemanticMCPBOM,
    SemanticTool,
    analyze_trace_provenance,
    bom_to_dict,
    build_semantic_bom,
    load_semantic_bom_config,
    representable_classes,
    run_bom_checks,
    score_bom_risk,
)


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

    # Semantic MCP-BOM
    "SemanticBOMConfig",
    "SemanticMCPBOM",
    "SemanticTool",
    "BOMFinding",
    "build_semantic_bom",
    "bom_to_dict",
    "load_semantic_bom_config",
    "run_bom_checks",
    "representable_classes",
    "score_bom_risk",
    "analyze_trace_provenance",
]
