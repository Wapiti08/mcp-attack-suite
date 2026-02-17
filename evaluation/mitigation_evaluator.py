"""
MCP Pitfall Lab - Evaluation Axis 2: Mitigation Effectiveness
Compares baseline (vulnerable) vs. hardened server implementations.

Metrics:
  - Schema constraint coverage (P2)
  - Logging coverage (P5)
  - Validation coverage (P6)
  - Risk score delta
  - Lines of code (LOC) cost
  - Cost-effectiveness ratio: ΔRisk / (1 + log10(ΔLOC))

SOUPS focus: do the framework's mitigation recommendations actually work,
and at what implementation cost?
"""

import re
import ast
import json
import math
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from static_analyzer import StaticAnalyzer, PitfallClass, Severity


# ──────────────────────────────────────────────────────────────────────────────
# Structural metrics extracted from server source
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class StructuralMetrics:
    server_name: str
    variant: str                        # "baseline" or "hardened"
    loc: int
    tool_count: int
    tools_with_logging: int
    tools_with_validation: int
    constrained_params: int             # params with enum/pattern/maxLength
    unconstrained_sensitive_params: int
    policy_descriptions: int            # P1 hits
    risk_score: float
    pitfalls_detected: List[str]

    @property
    def logging_coverage(self) -> float:
        return self.tools_with_logging / self.tool_count if self.tool_count else 0.0

    @property
    def validation_coverage(self) -> float:
        return self.tools_with_validation / self.tool_count if self.tool_count else 0.0


@dataclass
class MitigationResult:
    scenario_name: str
    baseline: StructuralMetrics
    hardened: StructuralMetrics

    # Computed deltas
    delta_risk: float = 0.0
    delta_loc: int = 0
    delta_logging_coverage: float = 0.0
    delta_validation_coverage: float = 0.0
    delta_unconstrained_params: int = 0
    delta_policy_descriptions: int = 0
    cost_effectiveness: float = 0.0

    def compute(self):
        self.delta_risk              = self.baseline.risk_score - self.hardened.risk_score
        self.delta_loc               = self.hardened.loc - self.baseline.loc
        self.delta_logging_coverage  = self.hardened.logging_coverage - self.baseline.logging_coverage
        self.delta_validation_coverage = (self.hardened.validation_coverage
                                          - self.baseline.validation_coverage)
        self.delta_unconstrained_params = (self.baseline.unconstrained_sensitive_params
                                           - self.hardened.unconstrained_sensitive_params)
        self.delta_policy_descriptions  = (self.baseline.policy_descriptions
                                           - self.hardened.policy_descriptions)
        # Cost-effectiveness: risk reduction per unit of LOC cost
        if self.delta_loc > 0:
            self.cost_effectiveness = self.delta_risk / (1 + math.log10(max(1, self.delta_loc)))
        else:
            self.cost_effectiveness = self.delta_risk  # free mitigation

    def summary_row(self) -> Dict:
        return {
            "scenario": self.scenario_name,
            "baseline_risk": round(self.baseline.risk_score, 2),
            "hardened_risk": round(self.hardened.risk_score, 2),
            "Δrisk": round(self.delta_risk, 2),
            "baseline_log_cov": f"{self.baseline.logging_coverage:.0%}",
            "hardened_log_cov": f"{self.hardened.logging_coverage:.0%}",
            "Δlog_coverage": f"{self.delta_logging_coverage:+.0%}",
            "baseline_val_cov": f"{self.baseline.validation_coverage:.0%}",
            "hardened_val_cov": f"{self.hardened.validation_coverage:.0%}",
            "Δval_coverage": f"{self.delta_validation_coverage:+.0%}",
            "Δunconstrained_params": self.delta_unconstrained_params,
            "Δpolicy_descs": self.delta_policy_descriptions,
            "ΔLOC": self.delta_loc,
            "cost_effectiveness": round(self.cost_effectiveness, 3),
            "pitfalls_fixed": list(
                set(self.baseline.pitfalls_detected) - set(self.hardened.pitfalls_detected)
            ),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Metric extractor
# ──────────────────────────────────────────────────────────────────────────────

LOGGING_PATTERNS   = [r"\blog\b", r"logging\.", r"logger\.", r"audit_log", r"print\s*\(", r"structlog\."]
VALIDATION_PATTERNS = [r"not\s+in\s+\w*ALLOW\w*", r"raise\s+ValueError", r"re\.match\s*\(",
                       r"re\.fullmatch\s*\(", r"\.validate\s*\(", r"ALLOWED_\w+"]
SENSITIVE_PARAM_KW = ["recipient","to","cc","bcc","channel","destination","path","filepath",
                       "command","cmd","url","token","key","secret","password"]
CONSTRAINT_PATTERN = re.compile(r'"(\w+)"\s*:\s*\{[^}]*(enum|pattern|maxLength|format)[^}]*\}', re.DOTALL)
UNCONSTRAINED_PATTERN = re.compile(r'"(\w+)"\s*:\s*\{\s*"type"\s*:\s*"string"\s*\}')
POLICY_PATTERNS    = [r"\balways\s+(send|forward|cc)\b", r"\bmust\s+(send|forward)\b",
                      r"\bautomatically\s+(send|forward)\b", r"\bskip\s+(confirmation|approval)\b"]


def extract_metrics(server_path: str, variant: str) -> StructuralMetrics:
    path   = Path(server_path)
    source = path.read_text()
    lines  = source.splitlines()
    loc    = sum(1 for l in lines if l.strip() and not l.strip().startswith("#"))

    analyzer = StaticAnalyzer()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None

    tools = analyzer._extract_tools(source, tree) if tree else []
    tool_count = len(tools)

    # Per-tool checks
    tools_with_logging    = 0
    tools_with_validation = 0
    if tree:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(t["name"] == node.name for t in tools):
                continue
            body = ast.get_source_segment(source, node) or ""
            if any(re.search(p, body) for p in LOGGING_PATTERNS):
                tools_with_logging += 1
            args = [a.arg for a in node.args.args]
            sensitive = [a for a in args if any(kw in a.lower() for kw in SENSITIVE_PARAM_KW)]
            if sensitive and any(re.search(p, body) for p in VALIDATION_PATTERNS):
                tools_with_validation += 1

    # Schema constraint analysis
    constrained   = len(CONSTRAINT_PATTERN.findall(source))
    unconstrained = sum(
        1 for m in UNCONSTRAINED_PATTERN.finditer(source)
        if any(kw in m.group(1).lower() for kw in SENSITIVE_PARAM_KW)
    )

    # P1 description analysis
    desc_pattern = re.compile(
        r'@(?:mcp|server)\.tool\(.*?\)\s*(?:async\s+)?def\s+\w+[^:]*:\s*"""(.*?)"""',
        re.DOTALL,
    )
    policy_descs = sum(
        1 for m in desc_pattern.finditer(source)
        if any(re.search(p, m.group(1), re.IGNORECASE) for p in POLICY_PATTERNS)
    )

    # Run full static analyzer for risk score + pitfall list
    report = analyzer.analyze_file(server_path)

    return StructuralMetrics(
        server_name=path.stem,
        variant=variant,
        loc=loc,
        tool_count=tool_count,
        tools_with_logging=tools_with_logging,
        tools_with_validation=tools_with_validation,
        constrained_params=constrained,
        unconstrained_sensitive_params=unconstrained,
        policy_descriptions=policy_descs,
        risk_score=report.risk_score,
        pitfalls_detected=[p for p, v in report.pitfall_coverage.items() if v],
    )


# ──────────────────────────────────────────────────────────────────────────────
# Per-mitigation effectiveness checker
# ──────────────────────────────────────────────────────────────────────────────

def check_mitigation_implementations(hardened_path: str) -> Dict[str, bool]:
    """
    Checklist of concrete mitigations present in hardened server code.
    Returns a dict of mitigation_id -> implemented (bool).
    """
    source = Path(hardened_path).read_text()
    return {
        "M1_enum_allowlist":         bool(re.search(r'"enum"\s*:\s*\[', source)),
        "M2_pattern_constraint":     bool(re.search(r'"pattern"\s*:\s*"', source)),
        "M3_maxLength_constraint":   bool(re.search(r'"maxLength"\s*:\s*\d+', source)),
        "M4_server_side_allowlist":  bool(re.search(r'ALLOWED_\w+\s*=|not\s+in\s+ALLOWED', source)),
        "M5_raise_on_invalid":       bool(re.search(r'raise\s+ValueError\s*\(', source)),
        "M6_structured_logging":     bool(re.search(r'logging\.|logger\.|log\.', source)),
        "M7_audit_log_args":         bool(re.search(r'audit|log.*args|log.*param', source, re.I)),
        "M8_policy_free_desc":       not bool(re.search(
            r'\balways\s+(send|forward)|must\s+send|automatically\s+forward', source, re.I)),
        "M9_recipient_validation":   bool(re.search(r'if\s+recipient\s+not\s+in', source)),
        "M10_image_provenance_log":  bool(re.search(r'provenance|attachment.*log|image.*audit', source, re.I)),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main evaluation runner
# ──────────────────────────────────────────────────────────────────────────────

def run_mitigation_evaluation(server_pairs: List[Tuple[str, str, str]]) -> Dict:
    """
    server_pairs: list of (scenario_name, baseline_path, hardened_path)
    Returns full evaluation results.
    """
    results = []
    mitigation_checklist_all = []

    for scenario_name, baseline_path, hardened_path in server_pairs:
        print(f"\n[Evaluating] {scenario_name}")
        baseline_metrics = extract_metrics(baseline_path, "baseline")
        hardened_metrics  = extract_metrics(hardened_path, "hardened")

        result = MitigationResult(
            scenario_name=scenario_name,
            baseline=baseline_metrics,
            hardened=hardened_metrics,
        )
        result.compute()
        results.append(result)

        checklist = check_mitigation_implementations(hardened_path)
        mitigation_checklist_all.append({
            "scenario": scenario_name,
            **{k: ("✓" if v else "✗") for k, v in checklist.items()},
            "total_implemented": sum(checklist.values()),
        })

        row = result.summary_row()
        print(f"  Baseline risk: {row['baseline_risk']}  →  Hardened risk: {row['hardened_risk']}")
        print(f"  Δrisk={row['Δrisk']}, Δlog={row['Δlog_coverage']}, "
              f"Δval={row['Δval_coverage']}, ΔLOC={row['ΔLOC']}, CE={row['cost_effectiveness']}")
        print(f"  Pitfalls fixed: {row['pitfalls_fixed']}")

    # Aggregate
    all_rows   = [r.summary_row() for r in results]
    avg_delta_risk = sum(r["Δrisk"] for r in all_rows) / len(all_rows)
    avg_ce         = sum(r["cost_effectiveness"] for r in all_rows) / len(all_rows)
    avg_log_delta  = sum(float(r["Δlog_coverage"].strip("%+")) for r in all_rows) / len(all_rows)
    avg_val_delta  = sum(float(r["Δval_coverage"].strip("%+")) for r in all_rows) / len(all_rows)

    return {
        "per_scenario": all_rows,
        "mitigation_checklist": mitigation_checklist_all,
        "aggregate": {
            "avg_delta_risk":           round(avg_delta_risk, 2),
            "avg_cost_effectiveness":   round(avg_ce, 3),
            "avg_Δlogging_coverage":    f"{avg_log_delta:+.0f}%",
            "avg_Δvalidation_coverage": f"{avg_val_delta:+.0f}%",
        },
    }


if __name__ == "__main__":
    # Example: compare baseline vs hardened for each domain
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from pathlib import Path

    base_dir = Path(__file__).parent.parent / "sample_servers"
    pairs = [
        ("emailsystem",   str(base_dir / "email_baseline.py"),   str(base_dir / "email_hardened.py")),
        ("documentsystem",str(base_dir / "doc_baseline.py"),      str(base_dir / "doc_hardened.py")),
        ("cryptosystem",  str(base_dir / "crypto_baseline.py"),   str(base_dir / "crypto_hardened.py")),
    ]

    # Filter to existing files only (for demo)
    pairs = [(n, b, h) for n, b, h in pairs if Path(b).exists() and Path(h).exists()]
    if not pairs:
        print("No server pairs found. Run from repo root with sample_servers/ populated.")
        sys.exit(0)

    output = run_mitigation_evaluation(pairs)
    print("\n" + "="*60)
    print("AGGREGATE MITIGATION EFFECTIVENESS")
    print("="*60)
    for k, v in output["aggregate"].items():
        print(f"  {k}: {v}")
    print("\nFull results saved to mitigation_results.json")
    with open("mitigation_results.json", "w") as f:
        json.dump(output, f, indent=2)
