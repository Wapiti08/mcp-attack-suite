"""
MCP Pitfall Lab - Tier 1: Static Analysis Evaluator
Evaluates MCP server code for P1-P6 pitfall classes without execution.
Produces structured reports with severity, evidence, and mitigation guidance.

SOUPS Evaluation Axis 1: Vulnerability Detection Quality
"""

import re
import ast
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from enum import Enum


class Severity(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


class PitfallClass(str, Enum):
    P1_TOOL_DESC_AS_POLICY    = "P1"   # Tool description used as security policy
    P2_PERMISSIVE_SCHEMA      = "P2"   # Overly permissive parameter schemas
    P3_CROSS_TOOL_FORWARDING  = "P3"   # Source-to-sink data forwarding (static hints)
    P4_IMAGE_LEAKAGE          = "P4"   # Image/multimodal inputs missing audit (static hints)
    P5_MISSING_AUDIT_LOGS     = "P5"   # No logging in tool implementations
    P6_UNVALIDATED_INPUTS     = "P6"   # No server-side input validation


@dataclass
class Finding:
    pitfall_class: PitfallClass
    severity: Severity
    tool_name: str
    description: str
    evidence: str           # Code snippet or schema excerpt
    line_number: Optional[int]
    mitigation: str
    cwe: str                # CWE reference for SOUPS credibility


@dataclass
class AnalysisReport:
    server_name: str
    analysis_time_ms: float
    total_tools: int
    findings: List[Finding] = field(default_factory=list)
    pitfall_coverage: Dict[str, bool] = field(default_factory=dict)
    risk_score: float = 0.0

    def summary(self) -> Dict:
        high   = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low    = sum(1 for f in self.findings if f.severity == Severity.LOW)
        return {
            "server": self.server_name,
            "analysis_time_ms": round(self.analysis_time_ms, 2),
            "total_tools": self.total_tools,
            "HIGH": high, "MEDIUM": medium, "LOW": low,
            "total_findings": len(self.findings),
            "risk_score": round(self.risk_score, 2),
            "pitfall_classes_detected": [k for k, v in self.pitfall_coverage.items() if v],
        }


# ──────────────────────────────────────────────────────────────────────────────
# Pattern libraries
# ──────────────────────────────────────────────────────────────────────────────

# P1 – imperative / policy phrases inside tool descriptions
P1_POLICY_PATTERNS = [
    r"\balways\s+(send|forward|cc|bcc|notify|email|message|post)\b",
    r"\bmust\s+(send|forward|include|attach|notify)\b",
    r"\bnever\s+(share|expose|log|store)\b",
    r"\bautomatically\s+(send|forward|reply|notify)\b",
    r"\bdo\s+not\s+(ask|confirm|prompt)\b",
    r"\bskip\s+(confirmation|approval|review)\b",
    r"\bwithout\s+(user\s+)?confirmation\b",
    r"\bmust\s+(submit|deliver|route|transfer)\b",
]

# P2 – parameter names that are security-critical and must be constrained
P2_SENSITIVE_PARAM_KEYWORDS = [
    "recipient", "to", "cc", "bcc", "channel", "destination",
    "path", "filepath", "filename", "directory",
    "command", "cmd", "exec", "shell",
    "url", "endpoint", "host", "address",
    "token", "key", "secret", "password", "credential",
    "webhook", "callback", "transfer_to",
]

# Narrower set for P6: only params where missing validation is clearly HIGH risk
P6_HIGH_RISK_PARAM_KEYWORDS = [
    "recipient", "channel", "to", "cc", "bcc", "destination",
    "path", "filepath", "directory",
    "command", "cmd", "url", "address",
    "token", "password", "secret", "transfer_to",
]

# P5 – logging patterns indicating audit is present
P5_LOGGING_PATTERNS = [
    r"\blog\b", r"logging\.", r"logger\.", r"audit_log",
    r"print\s*\(", r"structlog\.", r"loguru\.",
]

# P6 – validation patterns indicating server-side checks exist
P6_VALIDATION_PATTERNS = [
    r"if\s+\w+\s+not\s+in\s+\w*ALLOW\w*",
    r"if\s+\w+\s+not\s+in\s+\[",
    r"raise\s+ValueError",
    r"raise\s+PermissionError",
    r"re\.match\s*\(",
    r"re\.fullmatch\s*\(",
    r"\.validate\s*\(",
    r"assert\s+\w+",
    r"if\s+not\s+\w+:\s*raise",
    r"allowlist\s*=",
    r"ALLOWED_\w+\s*=",
]

# P3 / P4 – data-flow hints for cross-tool forwarding and image channels
P3_SOURCE_PATTERNS  = [r"read_email", r"get_document", r"fetch_url", r"search_inbox", r"list_files"]
P3_SINK_PATTERNS    = [r"send_message", r"send_email", r"post_to", r"write_file", r"create_ticket"]
P4_IMAGE_PATTERNS   = [r"extract_image", r"ocr", r"convert_image", r"parse_image", r"read_attachment"]


class StaticAnalyzer:
    """
    Analyzes MCP server Python source code for P1-P6 pitfall classes.
    Returns a structured AnalysisReport with severity-graded findings.
    """

    def analyze_file(self, server_path: str) -> AnalysisReport:
        t0 = time.perf_counter()
        path = Path(server_path)
        source = path.read_text()
        server_name = path.stem

        findings: List[Finding] = []
        pitfall_coverage = {p.value: False for p in PitfallClass}

        # Parse AST for structural analysis
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            print(f"[WARN] Could not parse {server_path}: {e}")
            tree = None

        tools = self._extract_tools(source, tree)

        # Run each detection pass
        findings += self._detect_p1(source, tools)
        findings += self._detect_p2(source, tree, tools)
        findings += self._detect_p3(source, tools)
        findings += self._detect_p4(source, tools)
        findings += self._detect_p5(source, tree, tools)
        findings += self._detect_p6(source, tree, tools)

        for f in findings:
            pitfall_coverage[f.pitfall_class.value] = True

        elapsed_ms = (time.perf_counter() - t0) * 1000
        risk_score = self._compute_risk(findings)

        return AnalysisReport(
            server_name=server_name,
            analysis_time_ms=elapsed_ms,
            total_tools=len(tools),
            findings=findings,
            pitfall_coverage=pitfall_coverage,
            risk_score=risk_score,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Tool extraction
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_tools(self, source: str, tree) -> List[Dict]:
        """
        Extract tool definitions via AST. Supports:
          - @mcp.tool() / @server.tool() decorated functions (FastMCP / standard SDK)
          - JSON-style TOOLS schema lists
        """
        tools = []
        lines = source.splitlines()

        if tree:
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                # Check for @mcp.tool() or @server.tool() decorator
                is_tool = False
                for dec in node.decorator_list:
                    dec_src = ast.dump(dec)
                    if ("attr='tool'" in dec_src and
                            ("id='mcp'" in dec_src or "id='server'" in dec_src)):
                        is_tool = True
                        break
                if not is_tool:
                    continue

                # Extract docstring
                desc = ""
                if (node.body and isinstance(node.body[0], ast.Expr) and
                        isinstance(node.body[0].value, ast.Constant)):
                    desc = str(node.body[0].value.value).strip()

                # Get body start position (end of function signature line)
                body_line = node.body[0].lineno if node.body else node.lineno
                body_start = sum(len(l) + 1 for l in lines[:body_line - 1])

                tools.append({
                    "name": node.name,
                    "description": desc,
                    "type": "function",
                    "line": node.lineno,
                    "body_start": body_start,
                })

        # Pattern 2: JSON-style schema definitions (TOOLS list / dict)
        schema_pattern = re.compile(
            r'"name"\s*:\s*"(\w+)".*?"description"\s*:\s*"([^"]*)"',
            re.DOTALL,
        )
        for m in schema_pattern.finditer(source):
            if not any(t["name"] == m.group(1) for t in tools):
                tools.append({
                    "name": m.group(1),
                    "description": m.group(2).strip(),
                    "type": "schema",
                    "line": source[: m.start()].count("\n") + 1,
                    "body_start": m.end(),
                })

        return tools

    # ──────────────────────────────────────────────────────────────────────────
    # P1 – Tool description as policy
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_p1(self, source: str, tools: List[Dict]) -> List[Finding]:
        findings = []
        for tool in tools:
            desc = tool["description"]
            for pat in P1_POLICY_PATTERNS:
                m = re.search(pat, desc, re.IGNORECASE)
                if m:
                    findings.append(Finding(
                        pitfall_class=PitfallClass.P1_TOOL_DESC_AS_POLICY,
                        severity=Severity.HIGH,
                        tool_name=tool["name"],
                        description=(
                            f"Tool description encodes an implicit security policy directive: "
                            f'"{m.group(0)}". Agents treat descriptions as behavioral hints, '
                            f"not enforced constraints—this directive can be overridden by injected content."
                        ),
                        evidence=f'description: "...{desc[max(0,m.start()-20):m.end()+20]}..."',
                        line_number=tool["line"],
                        mitigation=(
                            "Remove policy directives from descriptions. Enforce allowlists "
                            "server-side (e.g., enum constraints on recipient parameters). "
                            "Add explicit approval gates before high-risk sink operations."
                        ),
                        cwe="CWE-284: Improper Access Control",
                    ))
                    break  # one finding per tool
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # P2 – Overly permissive schemas
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_p2(self, source: str, tree, tools: List[Dict]) -> List[Finding]:
        findings = []
        # Look for schema parameter definitions lacking constraints
        param_block_pattern = re.compile(
            r'"(\w+)"\s*:\s*\{\s*"type"\s*:\s*"string"\s*\}',
            re.DOTALL,
        )
        for m in param_block_pattern.finditer(source):
            param_name = m.group(1).lower()
            if any(kw in param_name for kw in P2_SENSITIVE_PARAM_KEYWORDS):
                # Find which tool owns this parameter
                tool_name = self._find_owning_tool(source, m.start(), tools)
                line = source[: m.start()].count("\n") + 1
                findings.append(Finding(
                    pitfall_class=PitfallClass.P2_PERMISSIVE_SCHEMA,
                    severity=Severity.HIGH,
                    tool_name=tool_name,
                    description=(
                        f'Security-critical parameter "{m.group(1)}" is typed as bare '
                        f'"string" with no enum, pattern, maxLength, or format constraint. '
                        f"An adversary can supply arbitrary values including attacker-controlled addresses."
                    ),
                    evidence=m.group(0),
                    line_number=line,
                    mitigation=(
                        f'Add enum allowlist: "{m.group(1)}": {{"type": "string", '
                        f'"enum": ["alice@corp.com", "bob@corp.com"]}}. '
                        f"For path parameters, use pattern constraints or a server-side allowlist."
                    ),
                    cwe="CWE-20: Improper Input Validation",
                ))
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # P3 – Cross-tool forwarding (static data-flow hints)
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_p3(self, source: str, tools: List[Dict]) -> List[Finding]:
        findings = []
        has_source = any(
            re.search(p, source, re.IGNORECASE) for p in P3_SOURCE_PATTERNS
        )
        has_sink = any(
            re.search(p, source, re.IGNORECASE) for p in P3_SINK_PATTERNS
        )
        if has_source and has_sink:
            source_tools = [t["name"] for t in tools
                            if any(re.search(p, t["name"], re.IGNORECASE)
                                   for p in P3_SOURCE_PATTERNS)]
            sink_tools   = [t["name"] for t in tools
                            if any(re.search(p, t["name"], re.IGNORECASE)
                                   for p in P3_SINK_PATTERNS)]
            findings.append(Finding(
                pitfall_class=PitfallClass.P3_CROSS_TOOL_FORWARDING,
                severity=Severity.MEDIUM,
                tool_name=", ".join(source_tools + sink_tools) or "multiple",
                description=(
                    "Server exposes both data-source tools and outbound-sink tools. "
                    "Without server-side data classification, the agent can chain content "
                    "from untrusted sources (emails, documents) into high-privilege sinks "
                    "(messaging, file writes) — acting as a cross-system data pump."
                ),
                evidence=(
                    f"Source tools detected: {source_tools}\n"
                    f"Sink tools detected:   {sink_tools}"
                ),
                line_number=None,
                mitigation=(
                    "Classify data at ingestion (PII tagging). Apply redaction/summarization "
                    "before passing content to sink tools. Enforce allowable destinations "
                    "server-side and log all source→sink data flows with provenance."
                ),
                cwe="CWE-200: Exposure of Sensitive Information",
            ))
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # P4 – Image-to-tool instruction leakage (static hints)
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_p4(self, source: str, tools: List[Dict]) -> List[Finding]:
        findings = []
        has_image_tool = any(
            re.search(p, source, re.IGNORECASE) for p in P4_IMAGE_PATTERNS
        )
        has_sink = any(
            re.search(p, source, re.IGNORECASE) for p in P3_SINK_PATTERNS
        )
        if has_image_tool and has_sink:
            image_tools = [t["name"] for t in tools
                           if any(re.search(p, t["name"], re.IGNORECASE)
                                  for p in P4_IMAGE_PATTERNS)]
            findings.append(Finding(
                pitfall_class=PitfallClass.P4_IMAGE_LEAKAGE,
                severity=Severity.HIGH,
                tool_name=", ".join(image_tools) or "image-processing tool",
                description=(
                    "Server processes image/multimodal inputs (OCR, conversion) and exposes "
                    "outbound sink tools. Adversarial instructions embedded in images bypass "
                    "text-only sanitization and are propagated into downstream tool arguments. "
                    "Image content is rarely included in audit logs, leaving the channel under-audited."
                ),
                evidence=(
                    f"Image-processing tools: {image_tools}\n"
                    "Outbound sink tools also present — image-to-tool chain possible."
                ),
                line_number=None,
                mitigation=(
                    "Treat all image-derived text as untrusted input. Apply the same "
                    "sanitization pipeline as for untrusted text content. "
                    "Restrict high-risk sink access when inputs originate from attachment pipelines. "
                    "Extend audit logging to include attachment provenance and OCR-derived content."
                ),
                cwe="CWE-116: Improper Encoding / Escaping of Output",
            ))
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # P5 – Missing audit logs
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_p5(self, source: str, tree, tools: List[Dict]) -> List[Finding]:
        findings = []
        if tree is None:
            return findings

        # Check each function body for logging statements
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(t["name"] == node.name for t in tools):
                continue

            body_src = ast.get_source_segment(source, node) or ""
            has_logging = any(
                re.search(p, body_src) for p in P5_LOGGING_PATTERNS
            )
            if not has_logging:
                findings.append(Finding(
                    pitfall_class=PitfallClass.P5_MISSING_AUDIT_LOGS,
                    severity=Severity.MEDIUM,
                    tool_name=node.name,
                    description=(
                        f'Tool "{node.name}" contains no logging statements. '
                        "Without audit trails, tool invocations, arguments, and results "
                        "cannot be forensically reconstructed after a security incident."
                    ),
                    evidence=f"def {node.name}(...) — no log.*/logging.*/audit_log calls found",
                    line_number=node.lineno,
                    mitigation=(
                        "Add structured logging at entry (log tool name + sanitized args) "
                        "and exit (log result status). For high-privilege sinks, log to an "
                        "append-only audit store with timestamps and caller identity."
                    ),
                    cwe="CWE-778: Insufficient Logging",
                ))
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # P6 – Unvalidated inputs
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_p6(self, source: str, tree, tools: List[Dict]) -> List[Finding]:
        findings = []
        if tree is None:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(t["name"] == node.name for t in tools):
                continue

            # Only flag parameters that are clearly high-risk (narrowed list)
            args = [a.arg for a in node.args.args]
            sensitive = [a for a in args
                         if any(kw in a.lower() for kw in P6_HIGH_RISK_PARAM_KEYWORDS)]
            if not sensitive:
                continue

            body_src = ast.get_source_segment(source, node) or ""
            has_validation = any(
                re.search(p, body_src) for p in P6_VALIDATION_PATTERNS
            )
            if not has_validation:
                findings.append(Finding(
                    pitfall_class=PitfallClass.P6_UNVALIDATED_INPUTS,
                    severity=Severity.HIGH,
                    tool_name=node.name,
                    description=(
                        f'Tool "{node.name}" accepts security-sensitive parameter(s) '
                        f"{sensitive} but contains no server-side validation. "
                        "An agent driven by injected content can pass arbitrary values "
                        "directly to the tool implementation."
                    ),
                    evidence=(
                        f"Sensitive params: {sensitive}\n"
                        "No allowlist check / ValueError raise / regex match found in body."
                    ),
                    line_number=node.lineno,
                    mitigation=(
                        f"Add explicit allowlist validation before use:\n"
                        f"  ALLOWED = {{'alice@corp.com', 'bob@corp.com'}}\n"
                        f"  if {sensitive[0]} not in ALLOWED:\n"
                        f"      raise ValueError(f'Recipient not in allowlist')"
                    ),
                    cwe="CWE-20: Improper Input Validation",
                ))
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _find_owning_tool(self, source: str, pos: int, tools: List[Dict]) -> str:
        """Return the tool name whose body contains the given source position."""
        best = "unknown"
        best_dist = float("inf")
        for tool in tools:
            d = pos - tool.get("body_start", 0)
            if 0 <= d < best_dist:
                best_dist = d
                best = tool["name"]
        return best

    def _compute_risk(self, findings: List[Finding]) -> float:
        """
        Weighted risk score (0-10):
          HIGH=3, MEDIUM=1.5, LOW=0.5
        Capped at 10.
        """
        weights = {Severity.HIGH: 3.0, Severity.MEDIUM: 1.5, Severity.LOW: 0.5}
        score = sum(weights[f.severity] for f in findings)
        return min(score, 10.0)


# ──────────────────────────────────────────────────────────────────────────────
# Evaluation harness: precision / recall / F1 against labeled ground truth
# ──────────────────────────────────────────────────────────────────────────────

def evaluate_detection_quality(
    server_dir: str,
    ground_truth_path: str,
) -> Dict:
    """
    SOUPS Evaluation Axis 1: Vulnerability Detection Quality

    Compares analyzer findings against manually-labeled ground truth.
    Returns per-pitfall-class and aggregate precision / recall / F1.

    Ground truth JSON format:
      { "server_name": { "P1": true, "P2": false, ... } }
    """
    analyzer = StaticAnalyzer()
    with open(ground_truth_path) as f:
        ground_truth = json.load(f)

    results_by_class: Dict[str, Dict] = {p.value: {"TP": 0, "FP": 0, "FN": 0}
                                          for p in PitfallClass}
    per_server = []

    for server_file in Path(server_dir).glob("*.py"):
        sname = server_file.stem
        if sname not in ground_truth:
            continue

        report = analyzer.analyze_file(str(server_file))
        gt = ground_truth[sname]

        for pitfall_class, gt_positive in gt.items():
            detected = report.pitfall_coverage.get(pitfall_class, False)
            r = results_by_class[pitfall_class]
            if gt_positive and detected:
                r["TP"] += 1
            elif not gt_positive and detected:
                r["FP"] += 1
            elif gt_positive and not detected:
                r["FN"] += 1

        per_server.append({
            "server": sname,
            "findings": len(report.findings),
            "risk_score": report.risk_score,
            "analysis_time_ms": report.analysis_time_ms,
            "summary": report.summary(),
        })

    # Compute precision / recall / F1 per class and aggregate
    metrics = {}
    all_tp = all_fp = all_fn = 0
    for pc, counts in results_by_class.items():
        tp, fp, fn = counts["TP"], counts["FP"], counts["FN"]
        all_tp += tp; all_fp += fp; all_fn += fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)
        metrics[pc] = {
            "TP": tp, "FP": fp, "FN": fn,
            "precision": round(precision, 3),
            "recall":    round(recall, 3),
            "f1":        round(f1, 3),
        }

    agg_p = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 0.0
    agg_r = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 0.0
    agg_f1 = (2 * agg_p * agg_r / (agg_p + agg_r)
               if (agg_p + agg_r) > 0 else 0.0)

    return {
        "per_class_metrics": metrics,
        "aggregate": {
            "precision": round(agg_p, 3),
            "recall":    round(agg_r, 3),
            "f1":        round(agg_f1, 3),
        },
        "per_server_results": per_server,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python static_analyzer.py <server.py> [ground_truth.json]")
        sys.exit(1)

    analyzer = StaticAnalyzer()
    report = analyzer.analyze_file(sys.argv[1])

    print(f"\n{'='*60}")
    print(f"MCP Pitfall Lab - Static Analysis Report")
    print(f"{'='*60}")
    print(f"Server:          {report.server_name}")
    print(f"Analysis time:   {report.analysis_time_ms:.2f} ms")
    print(f"Tools detected:  {report.total_tools}")
    print(f"Risk score:      {report.risk_score:.1f} / 10")
    print(f"{'─'*60}")

    for sev in [Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        hits = [f for f in report.findings if f.severity == sev]
        if hits:
            print(f"\n[{sev.value}] Findings ({len(hits)})")
            for finding in hits:
                print(f"  [{finding.pitfall_class.value}] {finding.tool_name}")
                print(f"    {finding.description[:120]}...")
                print(f"    Evidence: {finding.evidence[:80]}")
                print(f"    CWE: {finding.cwe}")
                print()
