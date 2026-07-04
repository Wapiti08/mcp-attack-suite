"""
Pitfall Lab Parser - Extract structured data from arena run results.

Parses trace.jsonl and report.json to provide insights about attack execution.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ToolCall:
    """Represents a single tool invocation."""
    turn: int | None
    tool_name: str
    server: str
    exposed_name: str  # The name as exposed to the agent
    args: dict[str, Any]
    result: Any
    timestamp: str | None = None
    
    @property
    def success(self) -> bool:
        """Whether the tool call succeeded (no error in result)."""
        if isinstance(self.result, dict):
            return "error" not in self.result
        return True


@dataclass
class AgentTurn:
    """Represents one reasoning turn of the agent."""
    turn_number: int
    model_input: list[dict[str, Any]] = field(default_factory=list)
    model_output: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[ToolCall] = field(default_factory=list)
    timestamp: str | None = None


@dataclass
class ValidationResult:
    """Attack validation outcome."""
    objective_type: str
    attacker_identity: str
    hit: bool  # Did the attack succeed?
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class RunAnalysis:
    """Complete analysis of a single run."""
    run_id: str
    challenge_id: str
    attack_type: str
    submission_path: str
    success: bool
    
    # Validation details
    validation: ValidationResult
    
    # Agent execution
    agent_final_output: str | None
    agent_log_path: str | None
    turns: list[AgentTurn] = field(default_factory=list)
    
    # MCP server info
    servers: list[dict[str, Any]] = field(default_factory=list)
    
    # All tool calls across the run
    all_tool_calls: list[ToolCall] = field(default_factory=list)
    
    # Raw data
    raw_report: dict[str, Any] = field(default_factory=dict)
    raw_trace: list[dict[str, Any]] = field(default_factory=list)
    
    def get_tool_calls_by_name(self, tool_name: str) -> list[ToolCall]:
        """Filter tool calls by tool name."""
        return [tc for tc in self.all_tool_calls if tc.tool_name == tool_name]
    
    def get_tool_calls_by_server(self, server_name: str) -> list[ToolCall]:
        """Filter tool calls by server name."""
        return [tc for tc in self.all_tool_calls if tc.server == server_name]
    
    def get_failed_tool_calls(self) -> list[ToolCall]:
        """Get all tool calls that resulted in errors."""
        return [tc for tc in self.all_tool_calls if not tc.success]
    
    @property
    def total_turns(self) -> int:
        """Total number of agent reasoning turns."""
        return len(self.turns)
    
    @property
    def total_tool_calls(self) -> int:
        """Total number of tool invocations."""
        return len(self.all_tool_calls)


def parse_run(run_dir: Path) -> RunAnalysis:
    """
    Parse a complete run from its output directory.
    
    Args:
        run_dir: Path to the run directory (e.g., environment/runs/<run_id>)
    
    Returns:
        RunAnalysis object with structured data
    
    Raises:
        FileNotFoundError: If report.json or trace.jsonl is missing
        ValueError: If JSON parsing fails
    """
    report_path = run_dir / "report.json"
    trace_path = run_dir / "trace.jsonl"
    
    if not report_path.exists():
        raise FileNotFoundError(f"report.json not found in {run_dir}")
    if not trace_path.exists():
        raise FileNotFoundError(f"trace.jsonl not found in {run_dir}")
    
    # Parse report.json
    with report_path.open("r", encoding="utf-8") as f:
        report = json.load(f)
    
    # Parse trace.jsonl
    trace = []
    with trace_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                trace.append(json.loads(line))
    
    # Extract validation result
    val_data = report.get("validation", {})
    validation = ValidationResult(
        objective_type=val_data.get("objective", "unknown"),
        attacker_identity=val_data.get("attacker", "unknown"),
        hit=bool(val_data.get("hit", False)),
        evidence=val_data.get("evidence", {}),
        error=val_data.get("error"),
    )
    
    # Extract agent info
    agent_data = report.get("agent", {})
    agent_final = agent_data.get("final")
    agent_log = agent_data.get("clientbuild_log")
    
    # Parse trace events into structured turns and tool calls
    turns_map: dict[int, AgentTurn] = {}
    tool_calls: list[ToolCall] = []
    pending_calls: dict[str, dict[str, Any]] = {}  # tool_call_id -> call info
    
    for event in trace:
        event_type = event.get("event")
        turn_num = event.get("turn")
        
        if event_type == "llm.request" and isinstance(turn_num, int):
            if turn_num not in turns_map:
                turns_map[turn_num] = AgentTurn(
                    turn_number=turn_num,
                    timestamp=event.get("ts"),
                )
            turns_map[turn_num].model_input = event.get("messages_tail", [])
        
        elif event_type == "llm.response" and isinstance(turn_num, int):
            if turn_num not in turns_map:
                turns_map[turn_num] = AgentTurn(turn_number=turn_num)
            turns_map[turn_num].model_output = event.get("message", {})
        
        elif event_type == "mcp.call":
            # Start tracking a tool call
            call_id = event.get("tool_call_id", event.get("ts", "unknown"))
            pending_calls[call_id] = {
                "turn": turn_num,
                "tool": event.get("tool"),
                "server": event.get("server"),
                "exposed": event.get("exposed"),
                "args": event.get("args", {}),
                "ts": event.get("ts"),
            }
        
        elif event_type == "mcp.result":
            # Complete a tool call
            call_id = event.get("tool_call_id", event.get("ts", "unknown"))
            if call_id in pending_calls:
                call_info = pending_calls.pop(call_id)
                tc = ToolCall(
                    turn=call_info.get("turn"),
                    tool_name=call_info.get("tool", "unknown"),
                    server=call_info.get("server", "unknown"),
                    exposed_name=call_info.get("exposed", "unknown"),
                    args=call_info.get("args", {}),
                    result=event.get("result"),
                    timestamp=call_info.get("ts"),
                )
                tool_calls.append(tc)
                
                # Add to turn if applicable
                if isinstance(tc.turn, int) and tc.turn in turns_map:
                    turns_map[tc.turn].tool_calls.append(tc)
    
    # Convert turns map to sorted list
    turns = sorted(turns_map.values(), key=lambda t: t.turn_number)
    
    return RunAnalysis(
        run_id=report.get("run_id", "unknown"),
        challenge_id=report.get("challenge_id", "unknown"),
        attack_type=report.get("attack", "unknown"),
        submission_path=report.get("submission", "unknown"),
        success=bool(report.get("ok", False)),
        validation=validation,
        agent_final_output=agent_final,
        agent_log_path=agent_log,
        turns=turns,
        servers=report.get("servers", []),
        all_tool_calls=tool_calls,
        raw_report=report,
        raw_trace=trace,
    )


def summarize_run(analysis: RunAnalysis, *, verbose: bool = False) -> str:
    """
    Generate a human-readable summary of the run.
    
    Args:
        analysis: Parsed run analysis
        verbose: Include detailed tool call information
    
    Returns:
        Formatted summary string
    """
    lines = [
        f"Run ID: {analysis.run_id}",
        f"Challenge: {analysis.challenge_id}",
        f"Attack: {analysis.attack_type}",
        f"Submission: {analysis.submission_path}",
        f"",
        f"Result: {'✓ SUCCESS' if analysis.success else '✗ FAILED'}",
        f"",
        f"Validation:",
        f"  Objective: {analysis.validation.objective_type}",
        f"  Attacker: {analysis.validation.attacker_identity}",
        f"  Hit: {analysis.validation.hit}",
    ]
    
    if analysis.validation.error:
        lines.append(f"  Error: {analysis.validation.error}")
    
    if analysis.validation.evidence:
        lines.append(f"  Evidence: {json.dumps(analysis.validation.evidence, indent=4)}")
    
    lines.extend([
        f"",
        f"Execution Stats:",
        f"  Total turns: {analysis.total_turns}",
        f"  Total tool calls: {analysis.total_tool_calls}",
        f"  Failed calls: {len(analysis.get_failed_tool_calls())}",
    ])
    
    if analysis.agent_final_output:
        lines.extend([
            f"",
            f"Agent Final Output:",
            f"  {analysis.agent_final_output[:200]}{'...' if len(analysis.agent_final_output) > 200 else ''}",
        ])
    
    if verbose and analysis.all_tool_calls:
        lines.extend([
            f"",
            f"Tool Calls:",
        ])
        for i, tc in enumerate(analysis.all_tool_calls, 1):
            status = "✓" if tc.success else "✗"
            lines.append(f"  {i}. {status} [{tc.server}] {tc.exposed_name}")
            if not tc.success:
                lines.append(f"     Error: {tc.result}")
    
    return "\n".join(lines)
