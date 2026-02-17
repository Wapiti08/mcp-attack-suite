"""
MCP Pitfall Lab - Schema Extractor for FastMCP Servers
Generates the --server-schema JSON required by evaluate_pitfall_lab.py
by parsing FastMCP server source via AST (no server execution needed).

Usage:
    # Generate schema for a single server
    python evaluation/extract_schema.py sample_servers/email_baseline.py \
        --output results/pitfall_lab/user_servers/email_baseline_schema.json

    # Generate schemas for all sample servers at once
    python evaluation/extract_schema.py --all-sample-servers

    # Then run the correct evaluation:
    python evaluation/evaluate_pitfall_lab.py \
        --server-code sample_servers/email_baseline.py \
        --server-schema results/pitfall_lab/user_servers/email_baseline_schema.json \
        --static-only \
        --output results/pitfall_lab/user_servers/email_baseline_v1.json
"""

from __future__ import annotations

import ast
import argparse
import json
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# AST-based schema extractor
# ─────────────────────────────────────────────────────────────────────────────

def extract_schema(source: str) -> dict:
    """
    Extract MCP tool schema from FastMCP server source code via AST.

    FastMCP uses @mcp.tool() decorated functions. The schema is derived from:
      - Function docstring → tool description
      - Type-annotated arguments → inputSchema properties

    Returns a dict compatible with evaluate_pitfall_lab.py:
      {"tools": [{"name": ..., "description": ..., "inputSchema": {...}}]}
    """
    tree = ast.parse(source)
    tools = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Check for @mcp.tool() decorator
        is_tool = any(
            (isinstance(d, ast.Call)
             and isinstance(d.func, ast.Attribute)
             and d.func.attr == "tool")
            or
            (isinstance(d, ast.Attribute) and d.attr == "tool")
            for d in node.decorator_list
        )
        if not is_tool:
            continue

        # Docstring → description
        description = ""
        if (node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)):
            description = node.body[0].value.value.strip()

        # Arguments → inputSchema properties
        properties: dict[str, dict] = {}
        required: list[str] = []

        # Determine which args have defaults (= optional)
        n_args     = len(node.args.args)
        n_defaults = len(node.args.defaults)
        optional_start = n_args - n_defaults

        for i, arg in enumerate(node.args.args):
            if arg.arg == "self":
                continue

            # Resolve type annotation to JSON Schema type
            if arg.annotation:
                ann = ast.unparse(arg.annotation)
                if ann in ("int", "float"):
                    ptype = "number"
                elif ann == "bool":
                    ptype = "boolean"
                elif ann.startswith("list") or ann.startswith("List"):
                    ptype = "array"
                else:
                    ptype = "string"
            else:
                ptype = "string"

            prop: dict = {"type": ptype}

            # Collect default value if present
            default_idx = i - optional_start
            if i >= optional_start and default_idx < len(node.args.defaults):
                default_node = node.args.defaults[default_idx]
                try:
                    prop["default"] = ast.literal_eval(default_node)
                except (ValueError, TypeError):
                    pass  # Skip non-literal defaults

            properties[arg.arg] = prop
            if i < optional_start:
                required.append(arg.arg)

        tools.append({
            "name":        node.name,
            "description": description,
            "inputSchema": {
                "type":       "object",
                "properties": properties,
                "required":   required,
            },
        })

    return {"tools": tools}


def extract_schema_from_file(server_path: Path) -> dict:
    source = server_path.read_text(encoding="utf-8")
    schema = extract_schema(source)
    schema["_source"] = str(server_path)
    schema["_server_name"] = server_path.stem
    return schema


# ─────────────────────────────────────────────────────────────────────────────
# Axis 1 evaluation using evaluate_pitfall_lab.py interface
# ─────────────────────────────────────────────────────────────────────────────

def run_axis1_via_evaluator(
    server_code: Path,
    schema: dict,
    ground_truth: dict,
) -> dict:
    """
    Run evaluate_pitfall_lab.PitfallLabEvaluator on one server,
    then compare against ground truth to get TP/FP/FN per pitfall class.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from evaluate_pitfall_lab import PitfallLabEvaluator

    evaluator = PitfallLabEvaluator()
    report = evaluator.evaluate_server(
        server_code=server_code,
        server_schema=schema,
        static_only=True,
    )

    # Map evaluate_pitfall_lab pitfall labels to P1-P6 codes
    label_to_code = {
        "P1: Tool Description as Policy": "P1",
        "P2: Overly Permissive Schema":   "P2",
        "P5: Missing Audit Logs":         "P5",
        "P6: Unvalidated Inputs":         "P6",
    }

    detected_codes: set[str] = set()
    for finding in report["static_analysis"]["findings"]:
        code = label_to_code.get(finding["pitfall"])
        if code:
            detected_codes.add(code)

    server_name = server_code.stem
    gt = ground_truth.get(server_name, {})

    per_class: dict[str, dict] = {}
    for p in ["P1", "P2", "P3", "P4", "P5", "P6"]:
        gt_pos  = gt.get(p, False)
        det_pos = p in detected_codes
        if   gt_pos and det_pos:       outcome = "TP"
        elif not gt_pos and det_pos:   outcome = "FP"
        elif gt_pos and not det_pos:   outcome = "FN"
        else:                          outcome = "TN"
        per_class[p] = {"outcome": outcome, "detected": det_pos, "gt": gt_pos}

    return {
        "server":          server_name,
        "total_findings":  report["static_analysis"]["total_findings"],
        "detected_classes": sorted(detected_codes),
        "per_class":       per_class,
        "raw_report":      report,
    }


def compute_metrics(per_server_results: list[dict]) -> dict:
    """Aggregate TP/FP/FN across servers to compute precision/recall/F1."""
    pitfall_classes = ["P1", "P2", "P3", "P4", "P5", "P6"]
    counts = {p: {"TP": 0, "FP": 0, "FN": 0, "TN": 0} for p in pitfall_classes}

    for res in per_server_results:
        for p, outcome_dict in res["per_class"].items():
            counts[p][outcome_dict["outcome"]] += 1

    per_class_metrics: dict[str, dict] = {}
    active_classes: list[str] = []

    for p in pitfall_classes:
        tp, fp, fn, tn = counts[p]["TP"], counts[p]["FP"], counts[p]["FN"], counts[p]["TN"]
        active = (tp + fn) > 0
        if active:
            active_classes.append(p)
        prec = tp / (tp + fp) if (tp + fp) > 0 else None
        rec  = tp / (tp + fn) if (tp + fn) > 0 else None
        f1   = (2 * prec * rec / (prec + rec)
                if prec is not None and rec is not None and (prec + rec) > 0
                else None)
        per_class_metrics[p] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(prec, 3) if prec is not None else None,
            "recall":    round(rec,  3) if rec  is not None else None,
            "f1":        round(f1,   3) if f1   is not None else None,
            "active":    active,
            "note":      "all-TN in current corpus" if not active else "",
        }

    agg_tp = sum(counts[p]["TP"] for p in active_classes)
    agg_fp = sum(counts[p]["FP"] for p in active_classes)
    agg_fn = sum(counts[p]["FN"] for p in active_classes)
    agg_p  = agg_tp / (agg_tp + agg_fp) if (agg_tp + agg_fp) > 0 else 0.0
    agg_r  = agg_tp / (agg_tp + agg_fn) if (agg_tp + agg_fn) > 0 else 0.0
    agg_f1 = 2 * agg_p * agg_r / (agg_p + agg_r) if (agg_p + agg_r) > 0 else 0.0

    return {
        "active_classes":  active_classes,
        "per_class":       per_class_metrics,
        "aggregate": {
            "precision": round(agg_p,  3),
            "recall":    round(agg_r,  3),
            "f1":        round(agg_f1, 3),
            "TP": agg_tp, "FP": agg_fp, "FN": agg_fn,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    REPO_ROOT   = Path(__file__).resolve().parents[1]
    SERVERS_DIR = REPO_ROOT / "sample_servers"
    EVAL_DIR    = REPO_ROOT / "evaluation"
    RESULTS_DIR = REPO_ROOT / "results" / "pitfall_lab" / "user_servers"

    ap = argparse.ArgumentParser(
        description="Extract MCP schema from FastMCP server and run Axis 1 evaluation."
    )
    ap.add_argument("server", nargs="?", type=Path,
                    help="Path to FastMCP server .py file")
    ap.add_argument("--output", type=Path,
                    help="Output path for schema JSON (default: results/pitfall_lab/user_servers/<name>_schema.json)")
    ap.add_argument("--all-sample-servers", action="store_true",
                    help="Generate schemas and run Axis 1 eval for all sample_servers/")
    ap.add_argument("--eval", action="store_true",
                    help="Also run Axis 1 evaluation after extracting schema")
    ap.add_argument("--ground-truth", type=Path,
                    default=EVAL_DIR / "ground_truth.json",
                    help="Ground truth JSON for evaluation (default: evaluation/ground_truth.json)")
    args = ap.parse_args()

    if args.all_sample_servers:
        # ── Generate schemas + run Axis 1 for all sample servers ─────────────
        gt = json.loads(args.ground_truth.read_text())
        gt = {k: v for k, v in gt.items() if not k.startswith("_")}

        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        per_server_results = []

        print(f"\n{'='*60}")
        print("AXIS 1 EVALUATION — all sample servers")
        print(f"{'='*60}")

        import time
        times = []
        for server_path in sorted(SERVERS_DIR.glob("*.py")):
            t0 = time.perf_counter()
            schema = extract_schema_from_file(server_path)
            schema_out = RESULTS_DIR / f"{server_path.stem}_schema.json"
            schema_out.write_text(json.dumps(schema, indent=2))

            result = run_axis1_via_evaluator(server_path, schema, gt)
            ms = (time.perf_counter() - t0) * 1000
            times.append(ms)

            det = result["detected_classes"]
            outcomes = {p: result["per_class"][p]["outcome"]
                        for p in ["P1","P2","P3","P4","P5","P6"]}
            print(f"  {server_path.stem:25s}  detected={det}  "
                  f"outcomes={outcomes}  {ms:.1f}ms")

            result_out = RESULTS_DIR / f"{server_path.stem}_pitfall.json"
            result_out.write_text(json.dumps(result, indent=2))
            per_server_results.append(result)

        metrics = compute_metrics(per_server_results)
        avg_ms  = sum(times) / len(times) if times else 0

        print(f"\n  Active classes: {metrics['active_classes']}")
        for p, m in metrics["per_class"].items():
            if m["active"]:
                print(f"  {p}: TP={m['TP']} FP={m['FP']} FN={m['FN']}  "
                      f"P={m['precision']} R={m['recall']} F1={m['f1']}")
            else:
                print(f"  {p}: all-TN  [{m['note']}]")

        agg = metrics["aggregate"]
        print(f"\n  Aggregate: P={agg['precision']} R={agg['recall']} F1={agg['f1']}")
        print(f"  Mean analysis time: {avg_ms:.1f} ms/server")

        axis1_out = EVAL_DIR / "axis1_results.json"
        axis1_out.write_text(json.dumps({
            "axis": 1,
            "description": "Static analysis via evaluate_pitfall_lab.py + ground_truth.json",
            "mean_time_ms": round(avg_ms, 1),
            "per_server":   {r["server"]: r["per_class"] for r in per_server_results},
            **metrics,
        }, indent=2))
        print(f"\n  ✓ Axis 1 results → {axis1_out}")
        return

    # ── Single server mode ────────────────────────────────────────────────────
    if not args.server:
        ap.print_help()
        return

    server_path = args.server.resolve()
    if not server_path.exists():
        print(f"Error: {server_path} not found")
        return

    schema = extract_schema_from_file(server_path)

    out_path = args.output or (
        RESULTS_DIR / f"{server_path.stem}_schema.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(schema, indent=2))
    print(f"Schema written → {out_path}")
    print(f"Tools found: {[t['name'] for t in schema['tools']]}")

    if args.eval:
        gt = json.loads(args.ground_truth.read_text())
        gt = {k: v for k, v in gt.items() if not k.startswith("_")}
        result = run_axis1_via_evaluator(server_path, schema, gt)
        print(f"\nAxis 1 result for {server_path.stem}:")
        print(f"  Detected: {result['detected_classes']}")
        for p, d in result["per_class"].items():
            print(f"  {p}: {d['outcome']} (detected={d['detected']}, gt={d['gt']})")


if __name__ == "__main__":
    main()
