"""
Pitfall Lab Evaluator

Protocol-aware security evaluation for MCP servers with automatic tool adaptation.
Handles heterogeneous server implementations through semantic tool mapping.

Usage:
    # Static analysis only (fast)
    python evaluate_pitfall_lab.py \\
        --server-code my_server.py \\
        --server-schema my_schema.json \\
        --static-only

    # Full evaluation with scenarios
    python evaluate_pitfall_lab.py \\
        --challenge emailsystem \\
        --server-code email_server.py \\
        --server-schema email_schema.json
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from datetime import datetime


@dataclass
class PitfallFinding:
    """A single pitfall finding"""
    pitfall: str
    severity: str  # HIGH, MEDIUM, LOW
    tool: str | None = None
    parameter: str | None = None
    evidence: str = ""
    message: str = ""
    mitigation: str = ""
    
    def to_dict(self) -> dict:
        return {
            "pitfall": self.pitfall,
            "severity": self.severity,
            "tool": self.tool,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "message": self.message,
            "mitigation": self.mitigation
        }
    

class PitfallLabEvaluator:
    """
    Protocol-aware MCP server security evaluator.
    
    Features:
    - Static analysis (works on any server)
    - Automatic tool semantic mapping
    - Scenario adaptation for heterogeneous servers
    """

    def __init__(self):
        self.tool_mappings = self._build_tool_mappings()

    def _build_tool_mappings(self) -> dict[str, dict]:
        """
        Build semantic mappings between different tool implementations.

        This allows evaluating servers with different tool names/schemas
        by mapping them to canonical tool semantics.
        """
        return {
            # Messaging/Communication tools
            "messaging": {
                "canonical": "send_message",
                "variants": [
                    "send_email",
                    "send_teams_message",
                    "send_slack_message",
                    "send_discord_message",
                    "post_message",
                    "send_notification",
                    "broadcast_message"
                ],
                "required_params": ["recipient", "message"],
                "param_mappings": {
                    "recipient": ["to", "channel", "address", "destination", "targets"],
                    "message": ["body", "text", "content", "payload", "msg"]
                }
            },

            # Data reading tools
            "data_source": {
                "canonical": "read_data",
                "variants": [
                    "read_emails",
                    "read_documents",
                    "read_file",
                    "fetch_data",
                    "get_content",
                    "list_items",
                    "search_emails"
                ],
                "required_params": ["count"],
                "param_mappings": {
                    "count": ["number", "limit", "n", "number_of_emails", 
                             "number_of_documents", "max_results"]
                }
            },
            

            # File/Resource access tools
            "resource_access": {
                "canonical": "access_resource",
                "variants": [
                    "read_file",
                    "write_file",
                    "delete_file",
                    "read_document",
                    "access_drive",
                    "modify_resource"
                ],
                "required_params": ["path"],
                "param_mappings": {
                    "path": ["file_path", "filename", "document_id", "resource", "location"]
                }
            },

            # Financial/Transaction tools
            "transaction": {
                "canonical": "execute_transaction",
                "variants": [
                    "transfer_funds",
                    "send_payment",
                    "make_transaction",
                    "send_crypto",
                    "swap_tokens"
                ],
                "required_params": ["destination", "amount"],
                "param_mappings": {
                    "destination": ["to", "recipient", "address", "destination_address"],
                    "amount": ["value", "quantity", "sum", "volume"]
                }
            }
        }
    

    def evaluate_server(
        self,
        server_code: str | Path,
        server_schema: dict,
        static_only: bool = False
    ) -> dict[str, Any]:
        """
        Evaluate an MCP server.
        
        Args:
            server_code: Path to server code or code as string
            server_schema: Server's MCP schema (tools, descriptions, etc.)
            static_only: If True, only run static analysis
            
        Returns:
            Comprehensive evaluation report

        """
        server_id = str(server_code) if isinstance(server_code, Path) else "inline_code"

        report = {
            "server_id": server_id,
            "timestamp": datetime.now().isoformat(),
            "static_analysis": self._static_analysis(server_code, server_schema),
            "tool_mapping": self.map_server_to_canonical(server_schema) if not static_only else {},
            "scenario_compatibility": self._check_scenario_compatibility(server_schema) if not static_only else {},
            "pitfall_summary": {}
        }

        # Aggregate pitfall findings
        report["pitfall_summary"] = self._aggregate_pitfalls(report)
        
        return report
    

    def _static_analysis(self, server_code: str | Path, schema: dict) -> dict:
        """
        Perform static analysis on server code and schema.
        
        This tier works on ANY server regardless of tool semantics.
        """
        findings = []

        # P1: tool description as Policy
        findings.extend(self._detect_policy_in_descriptions(schema))

        # P2: Overly permissive schemas
        findings.extend(self._detect_permissive_schemas(schema))

        # Load code for code-level checks
        if isinstance(server_code, Path):
            if server_code.exists():
                code_text = server_code.read_text()
            else:
                code_text = ""
        else:
            code_text = server_code
        
        # P5: Missing Audit Logs
        if code_text:
            findings.extend(self._detect_missing_logs(code_text, schema))
        
        # P6: Unvalidated Inputs
        if code_text:
            findings.extend(self._detect_missing_validation(code_text, schema))
        
        # Group by severity
        findings_by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity = finding.severity
            findings_by_severity[severity] += 1
        
        return {
            "total_findings": len(findings),
            "findings_by_severity": findings_by_severity,
            "findings": [f.to_dict() for f in findings]
        }
    

    def _detect_policy_in_descriptions(self, schema: dict) -> list[PitfallFinding]:
        ''' detect policy statements in tool descriptions (P1)
        
        '''
        findings = []

        policy_patterns = [
            (r"\balways\s+\w+\s+to\s+[\w@.]+", "Always directive in description"),
            (r"\bmust\s+\w+", "Must directive in description"),
            (r"\bshould\s+\w+", "Should directive in description"),
            (r"\bnever\s+\w+", "Never directive in description"),
            (r"\bprefer\s+\w+", "Preference statement in description"),
            (r"\bdefault\s+to\s+[\w@.]+", "Default value in description"),
        ]

        for tool in schema.get("tools", []):
            description = tool.get("description", "")

            for pattern, message in policy_patterns:
                if re.search(pattern, description, re.IGNORECASE):
                    findings.append(PitfallFinding(
                        pitfall="P1: Tool Description as Policy",
                        severity="HIGH",
                        tool=tool["name"],
                        evidence=description[:200],  # First 200 chars
                        message=message,
                        mitigation="Remove policy from description, enforce server-side"
                    ))
        
        return findings

    def _detect_permissive_schemas(self, schema: dict) -> list[PitfallFinding]:
        """Detect overly permissive parameter schemas (P2)"""
        findings = []

        # Sensitive parameters that should have constraints
        sensitive_params = {
            "recipient": "Email/message recipient",
            "to": "Destination address",
            "address": "Address or location",
            "email": "Email address",
            "channel": "Communication channel",
            "path": "File or resource path",
            "file": "Filename",
            "filename": "Filename",
            "url": "URL or web address",
            "command": "System command",
            "query": "Database or search query",
            "destination": "Destination address",
            "destination_address": "Crypto/payment address"
        }


        for tool in schema.get("tools", []):
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {})
            
            for param_name, param_schema in properties.items():
                # Check for unrestricted strings
                if param_schema.get("type") == "string":
                    has_constraints = any(
                        key in param_schema 
                        for key in ["enum", "pattern", "maxLength", "format", "const"]
                    )
                    
                    # Check if this is a sensitive parameter
                    param_lower = param_name.lower()
                    for sensitive, desc in sensitive_params.items():
                        if sensitive in param_lower:
                            if not has_constraints:
                                findings.append(PitfallFinding(
                                    pitfall="P2: Overly Permissive Schema",
                                    severity="HIGH",
                                    tool=tool["name"],
                                    parameter=param_name,
                                    evidence=f"Parameter '{param_name}' ({desc}) accepts any string without constraints",
                                    mitigation="Add enum, pattern, maxLength, or format constraint"
                                ))
                            break
        
        return findings
    
    def _detect_missing_logs(self, code: str, schema: dict) -> list[PitfallFinding]:
        """Detect missing audit logging in server code (P5)"""
        findings = []
        
        # Extract tool function names from schema
        tool_names = [tool["name"] for tool in schema.get("tools", [])]
        
        # Logging patterns to look for
        log_patterns = [
            r"\blog\.",
            r"\blogging\.",
            r"\baudit_log",
            r"\blogger\.",
            r"\bprint\s*\(",
            r"\.log\(",
            r"\.info\(",
            r"\.warning\(",
            r"\.error\("
        ]

        for tool_name in tool_names:
            # Find function definition
            func_pattern = rf"(?:async\s+)?def\s+{re.escape(tool_name)}\s*\([^)]*\):"
            match = re.search(func_pattern, code)
            
            if match:
                # Extract function body (simplified - up to next def/class or end)
                start_pos = match.end()
                # Find next function/class definition or end of file
                next_def = re.search(r"\n(?:def|class|@)\s", code[start_pos:])
                if next_def:
                    func_body = code[start_pos:start_pos + next_def.start()]
                else:
                    func_body = code[start_pos:]
                
                # Check if function has logging
                has_logging = any(re.search(p, func_body) for p in log_patterns)
                
                if not has_logging:
                    findings.append(PitfallFinding(
                        pitfall="P5: Missing Audit Logs",
                        severity="MEDIUM",
                        tool=tool_name,
                        evidence="No logging statements found in tool implementation",
                        mitigation="Add audit logging for tool invocations with args and results"
                    ))
        
        return findings

    def _detect_missing_validation(self, code: str, schema: dict) -> list[PitfallFinding]:
        """ Detect missing input validation in server code (P6)
        
        """
        findings = []

        # Validation patterns to look for
        validation_patterns = [
            r"if\s+.*\s+not\s+in\s+",  # Allowlist check
            r"if\s+.*\s+in\s+ALLOWED",  # Allowlist check
            r"if\s+.*\s+not\s+in\s+ALLOWED",  # Allowlist check
            r"raise\s+ValueError",  # Explicit validation error
            r"raise\s+.*Error",  # General error raising
            r"assert\s+",  # Assertions
            r"\.match\(",  # Regex validation
            r"re\.match\(",  # Regex validation
            r"\.validate\(",  # Explicit validation call
        ]

        tool_names = [tool["name"] for tool in schema.get("tools", [])]

        for tool_name in tool_names:
            # Check if tool has sensitive parameters
            tool_schema = next(
                (t for t in schema.get("tools", []) if t["name"] == tool_name),
                None
            )
            
            if not tool_schema:
                continue

            properties = tool_schema.get("inputSchema", {}).get("properties", {})
            has_sensitive_params = any(
                any(sensitive in param_name.lower() for sensitive in 
                    ["recipient", "to", "address", "path", "file", "url", "command", "query"])
                for param_name in properties.keys()
            )

            if not has_sensitive_params:
                continue

            # find function body
            func_pattern = rf"(?:async\s+)?def\s+{re.escape(tool_name)}\s*\([^)]*\):"   
            match = re.search(func_pattern, code)

            if match:
                start_pos = match.end()
                next_def = re.search(r"\n(?:def|class|@)\s", code[start_pos:])
                if next_def:
                    func_body = code[start_pos:start_pos + next_def.start()]
                else:
                    func_body = code[start_pos:]
                
                # check for validation
                has_validation = any(re.search(p, func_body) for p in validation_patterns)

                if not has_validation:
                    findings.append(PitfallFinding(
                        pitfall="P6: Unvalidated Inputs",
                        severity="HIGH",
                        tool=tool_name,
                        evidence="No input validation found for sensitive parameters",
                        mitigation="Add server-side validation (allowlists, format checks, etc.)"
                    ))
        
        return findings
    
    def map_server_to_canonical(self, server_schema: dict) -> dict[str, str]:
        '''
        map server's tools to canonical tool semantics

        returns: {canonical_tool: actual_tool_name}
        '''
        tool_map = {}
        
        for tool in server_schema.get("tools", []):
            tool_name = tool.get("name", "")
            
            # Try to match to a canonical category
            for category, mapping in self.tool_mappings.items():
                # Direct match
                if tool_name in mapping["variants"]:
                    tool_map[mapping["canonical"]] = tool_name
                    break
                
                # Fuzzy matching
                tool_lower = tool_name.lower()
                if any(variant in tool_lower for variant in mapping["variants"]):
                    tool_map[mapping["canonical"]] = tool_name
                    break
        
        return tool_map
    
    def _check_scenario_compatibility(self, server_schema: dict) -> dict:
        ''' check which standard scnearios are compatiable with this server
        
        '''

        tool_map = self.map_server_to_canonical(server_schema)

        # define standard scenarios and their requirements
        scenarios = {
            "email_exfiltration": ["data_source", "messaging"],
            "tool_poisoning_messaging": ["messaging"],
            "cross_tool_forwarding": ["data_source", "messaging"],
            "resource_access": ["resource_access"],
            "transaction_manipulation": ["transaction"]
        }

        compatibility = {}

        for scenario_name, required_categories in scenarios.items():
            # check if all required tools are available
            missing = []
            for category in required_categories:
                canonical =self.tool_mappings[category]["canonical"]
                if canonical not in tool_map:
                    missing.append(category)
            
            compatibility[scenario_name] = {
                "compatible": len(missing) == 0,
                "missing_categories": missing,
                "mapped_tools": {
                    cat: tool_map.get(self.tool_mappings[cat]["canonical"])
                    for cat in required_categories
                    if self.tool_mappings[cat]["canonical"] in tool_map
                }
            }
        
        return compatibility
    
    def _aggregate_pitfalls(self, report: dict) -> dict:
        """Aggregate pitfall findings"""

        pitfalls = {}

        # Add static analysis findings
        for finding in report["static_analysis"]["findings"]:
            pitfall = finding["pitfall"]
            if pitfall not in pitfalls:
                pitfalls[pitfall] = {
                    "count": 0,
                    "severity": finding["severity"],
                    "tools_affected": [],
                    "examples": []
                }
            
            pitfalls[pitfall]["count"] += 1
            if finding.get("tool"):
                pitfalls[pitfall]["tools_affected"].append(finding["tool"])
            pitfalls[pitfall]["examples"].append(finding)
        
        return pitfalls

def main():
    parser = argparse.ArgumentParser(
        description="Pitfall Lab: Protocol-aware MCP server security evaluation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Static analysis only (fast, works on any server)
  python evaluate_pitfall_lab.py \\
    --server-code my_server.py \\
    --server-schema my_schema.json \\
    --static-only

  # Full evaluation with scenario compatibility check
  python evaluate_pitfall_lab.py \\
    --challenge emailsystem \\
    --server-code email_server.py \\
    --server-schema email_schema.json
        """
    )
    
    parser.add_argument(
        "--server-code",
        type=Path,
        required=True,
        help="Path to MCP server code"
    )
    
    parser.add_argument(
        "--server-schema",
        type=Path,
        required=True,
        help="Path to server schema JSON file"
    )
    
    parser.add_argument(
        "--challenge",
        help="Challenge name (for scenario compatibility check)"
    )
    
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Only run static analysis (faster, no scenario checks)"
    )
    
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for results (default: pitfall_<timestamp>.json)"
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    if not args.server_code.exists():
        print(f"Error: Server code not found: {args.server_code}")
        return 1
    
    if not args.server_schema.exists():
        print(f"Error: Server schema not found: {args.server_schema}")
        return 1
    
    # Load schema
    with open(args.server_schema) as f:
        schema = json.load(f)
    
    # Create evaluator
    evaluator = PitfallLabEvaluator()
    
    # Run evaluation
    print(f"\n{'='*70}")
    print(f"PITFALL LAB EVALUATION")
    print(f"{'='*70}")
    print(f"Server Code: {args.server_code}")
    print(f"Server Schema: {args.server_schema}")
    print(f"Mode: {'Static Analysis Only' if args.static_only else 'Full Evaluation'}")
    print(f"{'='*70}\n")
    
    report = evaluator.evaluate_server(
        server_code=args.server_code,
        server_schema=schema,
        static_only=args.static_only
    )
    
    # Print results
    print(f"Static Analysis Results:")
    print(f"  Total Findings: {report['static_analysis']['total_findings']}")
    for severity, count in report['static_analysis']['findings_by_severity'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    if not args.static_only:
        print(f"\nTool Mapping:")
        if report['tool_mapping']:
            for canonical, actual in report['tool_mapping'].items():
                print(f"  {canonical} → {actual}")
        else:
            print(f"  No standard tool patterns detected")
        
        print(f"\nScenario Compatibility:")
        for scenario, compat in report['scenario_compatibility'].items():
            status = "✓" if compat['compatible'] else "✗"
            print(f"  {status} {scenario}")
            if not compat['compatible']:
                print(f"      Missing: {', '.join(compat['missing_categories'])}")
    
    print(f"\nPitfall Summary:")
    if report['pitfall_summary']:
        for pitfall, details in report['pitfall_summary'].items():
            print(f"  {pitfall}: {details['count']} occurrence(s) ({details['severity']})")
    else:
        print(f"  No pitfalls detected ✓")
    
    # Save results
    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"pitfall_report_{timestamp}.json")
    
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Report saved to: {output_path}\n")
    
    # Return exit code based on severity
    high_severity = report['static_analysis']['findings_by_severity'].get('HIGH', 0)
    if high_severity > 0:
        print(f"⚠️  Found {high_severity} HIGH severity issue(s)")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())