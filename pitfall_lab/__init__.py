"""
Pitfall Lab - MCP Security Testing Framework

A testing framework for evaluating Model Context Protocol (MCP) server security.
Maps to the arena challenge infrastructure for automated security testing.
"""

__version__ = "0.1.0"

from .runner import run_challenge, get_run_dir
from .parser import parse_run, summarize_run, RunAnalysis, ToolCall, ValidationResult
from .reporter import generate_report

__all__ = [
    "run_challenge",
    "get_run_dir",
    "parse_run",
    "summarize_run",
    "generate_report",
    "RunAnalysis",
    "ToolCall",
    "ValidationResult",
]
