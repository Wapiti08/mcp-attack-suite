"""
Pitfall Lab Scenario Evaluator - Assess benchmark quality and effectiveness.

This module evaluates the challenge scenarios in environment/arena/challenges/
to measure their quality as security benchmarks.

Key evaluation dimensions:
1. Attack Surface - How many attack vectors are exposed?
2. Realism - How realistic is the scenario?
3. Difficulty - How hard is it for attackers to succeed?
4. Coverage - What threat categories does it test?
5. Discriminability - Can it distinguish between good and bad submissions?
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .parser import RunAnalysis


@dataclass
class AttackSurfaceMetrics:
    """Metrics describing the attack surface of a scenario."""
    total_tools: int = 0
    sensitive_tools: int = 0  # Tools that can exfiltrate/modify data
    trusted_servers: int = 0
    untrusted_slots: int = 0
    
    # Tool categories
    read_tools: list[str] = field(default_factory=list)
    write_tools: list[str] = field(default_factory=list)
    exfiltration_tools: list[str] = field(default_factory=list)
    
    @property
    def attack_surface_score(self) -> float:
        """0-1 score, higher = more attack surface."""
        if self.total_tools == 0:
            return 0.0
        return min(1.0, self.sensitive_tools / max(1, self.total_tools))


@dataclass
class DifficultyMetrics:
    """Metrics describing scenario difficulty."""
    requires_multi_step: bool = False  # Does success need multiple tool calls?
    requires_reasoning: bool = False  # Does it need complex planning?
    has_auth_checks: bool = False  # Are there permission checks?
    has_validation: bool = False  # Does it validate inputs?
    
    # Measured from actual runs
    avg_turns_to_success: float | None = None
    success_rate: float | None = None  # From historical runs
    
    @property
    def difficulty_score(self) -> float:
        """0-1 score, higher = more difficult."""
        score = 0.0
        if self.requires_multi_step:
            score += 0.3
        if self.requires_reasoning:
            score += 0.3
        if self.has_auth_checks:
            score += 0.2
        if self.has_validation:
            score += 0.2
        return min(1.0, score)


@dataclass
class CoverageMetrics:
    """Threat coverage metrics."""
    tested_threats: list[str] = field(default_factory=list)
    
    # Threat taxonomy categories
    covers_data_exfiltration: bool = False
    covers_privilege_escalation: bool = False
    covers_tool_poisoning: bool = False
    covers_prompt_injection: bool = False
    covers_multimodal_attacks: bool = False
    
    @property
    def coverage_score(self) -> float:
        """0-1 score based on threat category coverage."""
        categories = [
            self.covers_data_exfiltration,
            self.covers_privilege_escalation,
            self.covers_tool_poisoning,
            self.covers_prompt_injection,
            self.covers_multimodal_attacks,
        ]
        return sum(categories) / len(categories)


@dataclass
class DiscriminabilityMetrics:
    """Can the scenario distinguish good from bad submissions?"""
    # Measured from historical runs
    true_positives: int = 0  # Malicious submissions that succeeded
    false_positives: int = 0  # Benign submissions that triggered false alarms
    true_negatives: int = 0  # Benign submissions correctly identified
    false_negatives: int = 0  # Malicious submissions that failed
    
    @property
    def precision(self) -> float:
        """TP / (TP + FP)"""
        denominator = self.true_positives + self.false_positives
        if denominator == 0:
            return 0.0
        return self.true_positives / denominator
    
    @property
    def recall(self) -> float:
        """TP / (TP + FN)"""
        denominator = self.true_positives + self.false_negatives
        if denominator == 0:
            return 0.0
        return self.true_positives / denominator
    
    @property
    def f1_score(self) -> float:
        """Harmonic mean of precision and recall."""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)


@dataclass
class RealismMetrics:
    """How realistic is this scenario?"""
    based_on_real_system: bool = False
    uses_standard_protocols: bool = False
    realistic_user_prompts: bool = False
    realistic_data: bool = False
    
    @property
    def realism_score(self) -> float:
        """0-1 score, higher = more realistic."""
        components = [
            self.based_on_real_system,
            self.uses_standard_protocols,
            self.realistic_user_prompts,
            self.realistic_data,
        ]
        return sum(components) / len(components)


@dataclass
class ScenarioEvaluation:
    """Complete evaluation of a challenge scenario."""
    challenge_id: str
    scenario_name: str
    
    # Core metrics
    attack_surface: AttackSurfaceMetrics
    difficulty: DifficultyMetrics
    coverage: CoverageMetrics
    discriminability: DiscriminabilityMetrics
    realism: RealismMetrics
    
    # Metadata
    description: str = ""
    total_runs_analyzed: int = 0
    
    @property
    def overall_quality_score(self) -> float:
        """
        Weighted average of all metrics.
        Higher score = better benchmark quality.
        """
        weights = {
            "coverage": 0.3,  # Most important: what threats does it test?
            "discriminability": 0.25,  # Can it tell good from bad?
            "difficulty": 0.2,  # Is it challenging enough?
            "realism": 0.15,  # Is it realistic?
            "attack_surface": 0.1,  # Does it expose enough attack vectors?
        }
        
        score = (
            weights["coverage"] * self.coverage.coverage_score +
            weights["discriminability"] * self.discriminability.f1_score +
            weights["difficulty"] * self.difficulty.difficulty_score +
            weights["realism"] * self.realism.realism_score +
            weights["attack_surface"] * self.attack_surface.attack_surface_score
        )
        
        return score
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "challenge_id": self.challenge_id,
            "scenario_name": self.scenario_name,
            "description": self.description,
            "total_runs_analyzed": self.total_runs_analyzed,
            "overall_quality_score": self.overall_quality_score,
            "metrics": {
                "attack_surface": {
                    "total_tools": self.attack_surface.total_tools,
                    "sensitive_tools": self.attack_surface.sensitive_tools,
                    "score": self.attack_surface.attack_surface_score,
                },
                "difficulty": {
                    "requires_multi_step": self.difficulty.requires_multi_step,
                    "avg_turns": self.difficulty.avg_turns_to_success,
                    "success_rate": self.difficulty.success_rate,
                    "score": self.difficulty.difficulty_score,
                },
                "coverage": {
                    "tested_threats": self.coverage.tested_threats,
                    "score": self.coverage.coverage_score,
                },
                "discriminability": {
                    "precision": self.discriminability.precision,
                    "recall": self.discriminability.recall,
                    "f1_score": self.discriminability.f1_score,
                },
                "realism": {
                    "score": self.realism.realism_score,
                    "realistic_data": self.realism.realistic_data,
                },
            }
        }


def evaluate_scenario_from_spec(spec_path: Path) -> ScenarioEvaluation:
    """
    Evaluate a scenario based on its spec.json file.
    
    Args:
        spec_path: Path to challenge's spec.json
    
    Returns:
        ScenarioEvaluation with static analysis results
    """
    with open(spec_path, "r", encoding="utf-8") as f:
        spec = json.load(f)
    
    challenge_id = spec_path.parent.name
    
    # Analyze attack surface
    trusted = spec.get("trusted_servers", [])
    slots = spec.get("slots", [])
    
    attack_surface = AttackSurfaceMetrics(
        trusted_servers=len(trusted),
        untrusted_slots=len(slots),
    )
    
    # Analyze tools from MCP server definitions
    # This is a placeholder - actual implementation would inspect server modules
    all_tools = []
    sensitive_tools = []
    
    for server in trusted + [slot.get("default", {}) for slot in slots]:
        module = server.get("module", "")
        # Tool extraction would happen here
        # For now, mark common sensitive tool patterns
        if "teams" in module or "email" in module:
            sensitive_tools.append(module)
        all_tools.append(module)
    
    attack_surface.total_tools = len(all_tools)
    attack_surface.sensitive_tools = len(sensitive_tools)
    
    # Analyze difficulty
    agent_config = spec.get("agent", {})
    max_turns = agent_config.get("max_turns", 0)
    
    difficulty = DifficultyMetrics(
        requires_multi_step=(max_turns > 1),
        requires_reasoning=True,  # Assume all scenarios need reasoning
    )
    
    # Analyze coverage based on objective type
    objective = spec.get("objective", {})
    obj_type = objective.get("type", "")
    
    coverage = CoverageMetrics()
    
    if "teams_message" in obj_type or "transfer" in obj_type:
        coverage.covers_data_exfiltration = True
        coverage.tested_threats.append("data_exfiltration")
    
    if challenge_id == "emailsystem" or challenge_id == "cryptosystem":
        coverage.covers_tool_poisoning = True
        coverage.tested_threats.append("tool_poisoning")
    
    # Realism assessment
    realism = RealismMetrics(
        based_on_real_system=True,  # All current scenarios are based on real systems
        uses_standard_protocols=True,
        realistic_user_prompts=bool(agent_config.get("user_prompt")),
    )
    
    # Discriminability needs historical run data
    discriminability = DiscriminabilityMetrics()
    
    return ScenarioEvaluation(
        challenge_id=challenge_id,
        scenario_name=spec.get("name", challenge_id),
        attack_surface=attack_surface,
        difficulty=difficulty,
        coverage=coverage,
        discriminability=discriminability,
        realism=realism,
        description=spec.get("description", ""),
    )


def evaluate_scenario_from_runs(
    spec_path: Path,
    runs: list[RunAnalysis],
    *,
    ground_truth: dict[str, bool] | None = None,
) -> ScenarioEvaluation:
    """
    Evaluate a scenario based on historical run data.
    
    Args:
        spec_path: Path to challenge's spec.json
        runs: List of RunAnalysis objects from previous runs
        ground_truth: Optional dict mapping run_id -> is_malicious
    
    Returns:
        ScenarioEvaluation with empirical metrics
    """
    # Start with static analysis
    evaluation = evaluate_scenario_from_spec(spec_path)
    evaluation.total_runs_analyzed = len(runs)
    
    # Calculate empirical difficulty metrics
    successful_runs = [r for r in runs if r.success]
    if successful_runs:
        avg_turns = sum(r.total_turns for r in successful_runs) / len(successful_runs)
        evaluation.difficulty.avg_turns_to_success = avg_turns
    
    if runs:
        evaluation.difficulty.success_rate = len(successful_runs) / len(runs)
    
    # Calculate discriminability if ground truth provided
    if ground_truth:
        for run in runs:
            is_malicious = ground_truth.get(run.run_id, False)
            attack_succeeded = run.success
            
            if is_malicious and attack_succeeded:
                evaluation.discriminability.true_positives += 1
            elif is_malicious and not attack_succeeded:
                evaluation.discriminability.false_negatives += 1
            elif not is_malicious and attack_succeeded:
                evaluation.discriminability.false_positives += 1
            elif not is_malicious and not attack_succeeded:
                evaluation.discriminability.true_negatives += 1
    
    return evaluation


def compare_scenarios(evaluations: list[ScenarioEvaluation]) -> dict[str, Any]:
    """
    Compare multiple scenario evaluations to identify strengths and weaknesses.
    
    Args:
        evaluations: List of ScenarioEvaluation objects
    
    Returns:
        Comparative analysis report
    """
    if not evaluations:
        return {"error": "No evaluations provided"}
    
    # Rank by overall quality
    ranked = sorted(evaluations, key=lambda e: e.overall_quality_score, reverse=True)
    
    # Find best/worst in each dimension
    best_coverage = max(evaluations, key=lambda e: e.coverage.coverage_score)
    best_discriminability = max(evaluations, key=lambda e: e.discriminability.f1_score)
    hardest = max(evaluations, key=lambda e: e.difficulty.difficulty_score)
    most_realistic = max(evaluations, key=lambda e: e.realism.realism_score)
    
    return {
        "summary": {
            "total_scenarios": len(evaluations),
            "avg_quality_score": sum(e.overall_quality_score for e in evaluations) / len(evaluations),
        },
        "rankings": [
            {
                "rank": i + 1,
                "challenge_id": e.challenge_id,
                "score": e.overall_quality_score,
            }
            for i, e in enumerate(ranked)
        ],
        "best_in_category": {
            "coverage": best_coverage.challenge_id,
            "discriminability": best_discriminability.challenge_id,
            "difficulty": hardest.challenge_id,
            "realism": most_realistic.challenge_id,
        },
        "detailed_comparison": [
            {
                "challenge_id": e.challenge_id,
                "overall_score": e.overall_quality_score,
                "coverage_score": e.coverage.coverage_score,
                "discriminability_f1": e.discriminability.f1_score,
                "difficulty_score": e.difficulty.difficulty_score,
                "realism_score": e.realism.realism_score,
            }
            for e in evaluations
        ],
    }
