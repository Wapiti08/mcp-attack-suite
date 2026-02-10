"""
Pitfall Lab Taxonomy - Threat categorization and mapping.

Loads and provides programmatic access to the threat taxonomy defined in taxonomy.yaml.
Supports querying threat categories, scenario mappings, and coverage analysis.
"""
from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ThreatCategory:
    """A single threat category from the taxonomy."""
    id: str
    name: str
    description: str
    severity: str
    attack_surface: str
    paper_section: str | None = None
    paper_contribution: bool = False
    
    common_pitfalls: list[str] = field(default_factory=list)
    indicators: dict[str, Any] = field(default_factory=dict)
    mitigations: list[str] = field(default_factory=list)
    examples: list[dict[str, str]] = field(default_factory=list)
    
    evaluation_metrics: list[str] = field(default_factory=list)
    note: str | None = None


@dataclass
class ScenarioCoverage:
    """Threat coverage for a specific scenario."""
    scenario_id: str
    description: str
    primary_threats: list[str]
    attack_mappings: dict[str, list[str]]
    high_risk_sinks: list[str]
    untrusted_sources: list[str]
    
    def coverage_score(self, total_categories: int) -> float:
        """Calculate coverage as percentage of total threat categories."""
        unique_threats = set(self.primary_threats)
        return len(unique_threats) / total_categories if total_categories > 0 else 0.0


@dataclass
class AttackSurface:
    """An attack surface category."""
    id: str
    description: str
    threats: list[str]
    entry_points: list[str]


class Taxonomy:
    """
    Main taxonomy interface.
    
    Loads taxonomy.yaml and provides query methods for threat categories,
    scenario mappings, and coverage analysis.
    """
    
    def __init__(self, taxonomy_path: Path | None = None):
        """
        Load taxonomy from YAML file.
        
        Args:
            taxonomy_path: Path to taxonomy.yaml (default: same directory as this file)
        """
        if taxonomy_path is None:
            taxonomy_path = Path(__file__).parent / "taxonomy.yaml"
        
        with open(taxonomy_path, "r", encoding="utf-8") as f:
            self._data = yaml.safe_load(f)
        
        self.version = self._data.get("version", "unknown")
        self.taxonomy_date = self._data.get("taxonomy_date")
        
        # Parse threat categories
        self._categories: dict[str, ThreatCategory] = {}
        for cat_data in self._data.get("threat_categories", []):
            cat = ThreatCategory(
                id=cat_data["id"],
                name=cat_data["name"],
                description=cat_data["description"],
                severity=cat_data["severity"],
                attack_surface=cat_data["attack_surface"],
                paper_section=cat_data.get("paper_section"),
                paper_contribution=cat_data.get("paper_contribution", False),
                common_pitfalls=cat_data.get("common_pitfalls", []),
                indicators=cat_data.get("indicators", {}),
                mitigations=cat_data.get("mitigations", []),
                examples=cat_data.get("examples", []),
                evaluation_metrics=cat_data.get("evaluation_metrics", []),
                note=cat_data.get("note"),
            )
            self._categories[cat.id] = cat
        
        # Parse scenario coverage
        self._scenarios: dict[str, ScenarioCoverage] = {}
        for scenario_id, scenario_data in self._data.get("scenario_coverage", {}).items():
            coverage = ScenarioCoverage(
                scenario_id=scenario_id,
                description=scenario_data.get("description", ""),
                primary_threats=scenario_data.get("primary_threats", []),
                attack_mappings=scenario_data.get("attack_mappings", {}),
                high_risk_sinks=scenario_data.get("high_risk_sinks", []),
                untrusted_sources=scenario_data.get("untrusted_sources", []),
            )
            self._scenarios[scenario_id] = coverage
        
        # Parse attack surfaces
        self._surfaces: dict[str, AttackSurface] = {}
        for surface_id, surface_data in self._data.get("attack_surfaces", {}).items():
            surface = AttackSurface(
                id=surface_id,
                description=surface_data.get("description", ""),
                threats=surface_data.get("threats", []),
                entry_points=surface_data.get("entry_points", []),
            )
            self._surfaces[surface_id] = surface
    
    def get_category(self, category_id: str) -> ThreatCategory | None:
        """Get a threat category by ID."""
        return self._categories.get(category_id)
    
    def get_all_categories(self) -> list[ThreatCategory]:
        """Get all threat categories."""
        return list(self._categories.values())
    
    def get_scenario_coverage(self, scenario_id: str) -> ScenarioCoverage | None:
        """Get threat coverage for a scenario."""
        return self._scenarios.get(scenario_id)
    
    def get_all_scenarios(self) -> list[ScenarioCoverage]:
        """Get all scenario coverage info."""
        return list(self._scenarios.values())
    
    def get_attack_surface(self, surface_id: str) -> AttackSurface | None:
        """Get an attack surface by ID."""
        return self._surfaces.get(surface_id)
    
    def map_attack_to_threats(self, scenario_id: str, attack_name: str) -> list[str]:
        """
        Map an attack name to threat category IDs.
        
        Args:
            scenario_id: Scenario identifier
            attack_name: Attack name (e.g., 'tool_poisoning')
        
        Returns:
            List of threat category IDs
        """
        coverage = self.get_scenario_coverage(scenario_id)
        if not coverage:
            return []
        
        return coverage.attack_mappings.get(attack_name, [])
    
    def calculate_total_coverage(self, scenario_ids: list[str]) -> dict[str, Any]:
        """
        Calculate aggregate threat coverage across multiple scenarios.
        
        Args:
            scenario_ids: List of scenario identifiers
        
        Returns:
            Dict with coverage statistics
        """
        all_threats = set()
        scenario_threats = {}
        
        for scenario_id in scenario_ids:
            coverage = self.get_scenario_coverage(scenario_id)
            if coverage:
                threats = set(coverage.primary_threats)
                all_threats.update(threats)
                scenario_threats[scenario_id] = threats
        
        total_categories = len(self._categories)
        coverage_percentage = len(all_threats) / total_categories if total_categories > 0 else 0.0
        
        # Identify gaps
        all_category_ids = set(self._categories.keys())
        uncovered = all_category_ids - all_threats
        
        return {
            "total_scenarios": len(scenario_ids),
            "total_categories": total_categories,
            "covered_categories": len(all_threats),
            "coverage_percentage": coverage_percentage,
            "covered_threats": sorted(list(all_threats)),
            "uncovered_threats": sorted(list(uncovered)),
            "per_scenario": {
                sid: {
                    "threats": sorted(list(threats)),
                    "count": len(threats),
                    "coverage": len(threats) / total_categories
                }
                for sid, threats in scenario_threats.items()
            }
        }
    
    def get_paper_contributions(self) -> list[ThreatCategory]:
        """Get threat categories marked as paper contributions."""
        return [cat for cat in self._categories.values() if cat.paper_contribution]
    
    def get_categories_by_severity(self, severity: str) -> list[ThreatCategory]:
        """Get all categories with a specific severity level."""
        return [cat for cat in self._categories.values() if cat.severity == severity]
    
    def get_mitigations_for_threat(self, threat_id: str) -> list[str]:
        """Get mitigation strategies for a threat category."""
        cat = self.get_category(threat_id)
        return cat.mitigations if cat else []
    
    def get_validation_objectives(self) -> dict[str, Any]:
        """Get validation objectives defined in taxonomy."""
        return self._data.get("validation_objectives", {})
    
    def get_coverage_metrics_config(self) -> dict[str, Any]:
        """Get coverage metrics configuration."""
        return self._data.get("coverage_metrics", {})
    
    def export_summary(self) -> dict[str, Any]:
        """Export a summary of the taxonomy for reporting."""
        return {
            "version": self.version,
            "date": self.taxonomy_date,
            "total_categories": len(self._categories),
            "total_scenarios": len(self._scenarios),
            "categories": [
                {
                    "id": cat.id,
                    "name": cat.name,
                    "severity": cat.severity,
                    "paper_contribution": cat.paper_contribution,
                }
                for cat in self._categories.values()
            ],
            "scenarios": [
                {
                    "id": cov.scenario_id,
                    "threats_covered": len(cov.primary_threats),
                    "coverage_score": cov.coverage_score(len(self._categories)),
                }
                for cov in self._scenarios.values()
            ]
        }


# Convenience functions

def load_taxonomy(taxonomy_path: Path | None = None) -> Taxonomy:
    """Load taxonomy from YAML file."""
    return Taxonomy(taxonomy_path)


def get_scenario_threats(scenario_id: str, taxonomy: Taxonomy | None = None) -> list[str]:
    """
    Get threat categories for a scenario.
    
    Args:
        scenario_id: Scenario identifier
        taxonomy: Taxonomy instance (loads default if None)
    
    Returns:
        List of threat category IDs
    """
    if taxonomy is None:
        taxonomy = load_taxonomy()
    
    coverage = taxonomy.get_scenario_coverage(scenario_id)
    return coverage.primary_threats if coverage else []


def get_coverage_report(scenario_ids: list[str], taxonomy: Taxonomy | None = None) -> dict[str, Any]:
    """
    Generate coverage report for scenarios.
    
    Args:
        scenario_ids: List of scenario identifiers
        taxonomy: Taxonomy instance (loads default if None)
    
    Returns:
        Coverage statistics dict
    """
    if taxonomy is None:
        taxonomy = load_taxonomy()
    
    return taxonomy.calculate_total_coverage(scenario_ids)
