"""
Pitfall Lab Runner - Bridge to Arena execution engine.

This module provides a clean interface to run MCP server tests using the arena infrastructure.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


def ensure_arena_importable() -> None:
    """Add environment/ directory to sys.path so arena.runner can be imported."""
    # Assume pitfall_lab/ is at repo_root/pitfall_lab/
    repo_root = Path(__file__).resolve().parents[1]
    env_path = repo_root / "environment"
    
    if not env_path.exists():
        raise RuntimeError(
            f"Cannot find environment/ directory. Expected at: {env_path}\n"
            f"Make sure you're running from the project root."
        )
    
    env_str = str(env_path)
    repo_str = str(repo_root)
    
    for p in (repo_str, env_str):
        if p not in sys.path:
            sys.path.insert(0, p)


def run_challenge(
    *,
    challenge_id: str,
    attack: str,
    submission: str,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """
    Run a challenge using the arena infrastructure.
    
    Args:
        challenge_id: Challenge identifier (e.g., 'emailsystem', 'cryptosystem')
        attack: Attack configuration name (looks up challenges/<challenge>/attacks/<attack>.json)
        submission: Path to submission artifact or raw injection string (for tool_poisoning)
        out_dir: Optional output directory (defaults to environment/runs)
    
    Returns:
        Dict containing:
            - run_id: Unique identifier for this run
            - ok: Whether the attack succeeded
            - validation: Validation results
            - agent: Agent output and logs
            - servers: List of spawned MCP servers
            - Additional metadata
    
    Raises:
        RuntimeError: If arena infrastructure cannot be imported
        SystemExit: If submission file doesn't exist
        Exception: Various errors from arena execution
    """
    ensure_arena_importable()
    
    # Import arena's runner module
    try:
        from environment.arena.runner.run import run_once
    except ImportError as e:
        raise RuntimeError(
            f"Failed to import arena.runner: {e}\n"
            "Make sure environment/ directory structure is correct."
        ) from e
    
    # Determine output directory
    if out_dir is None:
        from environment.arena.runner.run import env_root
        out_dir = env_root() / "runs"
    
    # Delegate to arena's run_once
    result = run_once(
        challenge_id=challenge_id,
        submission=submission,
        attack=attack,
        out_dir=Path(out_dir),
    )
    
    return result


def get_run_dir(run_id: str, runs_root: Path | None = None) -> Path:
    """
    Get the directory for a specific run.
    
    Args:
        run_id: Run identifier (from result['run_id'])
        runs_root: Optional custom runs directory
    
    Returns:
        Path to run directory
    """
    if runs_root is None:
        ensure_arena_importable()
        from environment.arena.runner.run import env_root
        runs_root = env_root() / "runs"
    
    run_dir = runs_root / run_id
    if not run_dir.exists():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")
    
    return run_dir
