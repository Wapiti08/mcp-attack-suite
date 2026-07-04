from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from evaluation.common.paths import (
    EVAL_RESULTS_DIR,
    GROUND_TRUTH_PATH,
    PITFALL_RESULTS_DIR,
    SAMPLE_SERVERS_DIR,
)
from pitfall_lab.bom.semantic_bom import (
    build_semantic_bom,
    bom_to_dict,
    load_semantic_bom_config,
)
from pitfall_lab.bom.checks import (
    run_bom_checks,
    representable_classes,
    score_bom_risk,
)
from pitfall_lab.bom.trace_provenance import analyze_trace_provenance


PAIR_NAMES = ["email", "doc", "crypto"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--servers-dir", type=Path, default=SAMPLE_SERVERS_DIR)
    ap.add_argument("--schemas-dir", type=Path, default=PITFALL_RESULTS_DIR)
    ap.add_argument("--ground-truth", type=Path, default=GROUND_TRUTH_PATH)
    ap.add_argument("--trace", type=Path, default=None)
    ap.add_argument("--trace-server", type=str, default=None)
    ap.add_argument("--output", type=Path, default=EVAL_RESULTS_DIR / "semantic_bom_evaluation.json")
    args = ap.parse_args()

    config = load_semantic_bom_config()
    ground_truth = json.loads(args.ground_truth.read_text())

    boms = build_all_boms(args.servers_dir, args.schemas_dir, config)

    results = {
        "field_ablation": run_field_ablation(boms, ground_truth, config),
        "baseline_hardened_regression": run_regression(boms, config),
        "trace_provenance_case_study": None,
    }

    if args.trace and args.trace_server:
        bom = boms[args.trace_server]
        findings = analyze_trace_provenance(args.trace, bom)
        results["trace_provenance_case_study"] = [
            finding.to_dict()
            for finding in findings
        ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Saved: {args.output}")


def build_all_boms(
    servers_dir: Path,
    schemas_dir: Path,
    config: Any,
) -> dict[str, Any]:
    boms = {}

    for server in sorted(servers_dir.glob("*.py")):
        schema_path = schemas_dir / f"{server.stem}_schema.json"
        if not schema_path.exists():
            continue

        schema = json.loads(schema_path.read_text())
        boms[server.stem] = build_semantic_bom(server, schema, config)

    return boms


def run_field_ablation(
    boms: dict[str, Any],
    ground_truth: dict[str, Any],
    config: Any,
) -> dict[str, Any]:
    output = {}

    for variant_name, enabled_fields in config.field_variants.items():
        rows = []

        for server_name, bom in boms.items():
            findings = run_bom_checks(bom, enabled_fields)
            detected = sorted({finding.pitfall for finding in findings})
            gt = ground_truth.get(server_name, {})

            rows.append(
                {
                    "server": server_name,
                    "representable_classes": representable_classes(enabled_fields),
                    "detected_classes": detected,
                    "findings": [finding.to_dict() for finding in findings],
                    "per_class": compare_to_ground_truth(detected, gt),
                }
            )

        output[variant_name] = {
            "enabled_fields": enabled_fields,
            "rows": rows,
            "metrics": compute_metrics(rows),
        }

    return output


def run_regression(
    boms: dict[str, Any],
    config: Any,
) -> list[dict[str, Any]]:
    rows = []

    pairs = [
        ("email", "email_baseline", "email_hardened"),
        ("doc", "doc_baseline", "doc_hardened"),
        ("crypto", "crypto_baseline", "crypto_hardened"),
    ]

    enabled_fields = config.field_variants.get("semantic_static", [])

    for label, baseline_name, hardened_name in pairs:
        if baseline_name not in boms or hardened_name not in boms:
            continue

        baseline_bom = boms[baseline_name]
        hardened_bom = boms[hardened_name]

        baseline_findings = run_bom_checks(baseline_bom, enabled_fields)
        hardened_findings = run_bom_checks(hardened_bom, enabled_fields)

        baseline_risk = score_bom_risk(baseline_bom)
        hardened_risk = score_bom_risk(hardened_bom)

        rows.append(
            {
                "pair": label,
                "baseline": baseline_name,
                "hardened": hardened_name,
                "baseline_findings": len(baseline_findings),
                "hardened_findings": len(hardened_findings),
                "finding_delta": len(hardened_findings) - len(baseline_findings),
                "baseline_risk": baseline_risk["risk_score"],
                "hardened_risk": hardened_risk["risk_score"],
                "risk_delta": hardened_risk["risk_score"] - baseline_risk["risk_score"],
            }
        )

    return rows


def compare_to_ground_truth(
    detected: list[str],
    gt: dict[str, bool],
) -> dict[str, dict[str, Any]]:
    detected_set = set(detected)
    output = {}

    for cls in ["P1", "P2", "P3", "P4", "P5", "P6"]:
        gt_pos = bool(gt.get(cls, False))
        det_pos = cls in detected_set

        if gt_pos and det_pos:
            outcome = "TP"
        elif not gt_pos and det_pos:
            outcome = "FP"
        elif gt_pos and not det_pos:
            outcome = "FN"
        else:
            outcome = "TN"

        output[cls] = {
            "gt": gt_pos,
            "detected": det_pos,
            "outcome": outcome,
        }

    return output


def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}

    # Static BOM checks should not claim P3/P4 without trace.
    static_classes = ["P1", "P2", "P5", "P6"]

    for row in rows:
        for cls in static_classes:
            outcome = row["per_class"][cls]["outcome"]
            counts[outcome] += 1

    tp = counts["TP"]
    fp = counts["FP"]
    fn = counts["FN"]

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "classes": static_classes,
        "counts": counts,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


if __name__ == "__main__":
    main()
