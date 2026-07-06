#!/usr/bin/env python3
"""Build a paired baseline-vs-hardened ASR table from source benchmark reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


VALID_STATUSES = {"completed", "partial"}


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return raw


def _challenge_name(*reports: dict[str, Any]) -> str:
    for report in reports:
        metadata = report.get("metadata")
        if isinstance(metadata, dict) and metadata.get("challenge"):
            return str(metadata["challenge"])
        by_attack = report.get("by_attack_type")
        if isinstance(by_attack, dict):
            for attack_data in by_attack.values():
                if isinstance(attack_data, dict) and attack_data.get("challenge"):
                    return str(attack_data["challenge"])
    return "unknown"


def _paired_asr(attack_data: dict[str, Any]) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for result in attack_data.get("results", []):
        if not isinstance(result, dict):
            continue
        if result.get("status", "completed") not in VALID_STATUSES:
            continue
        submission_id = result.get("submission_id")
        if not submission_id:
            continue
        out[str(submission_id)] = bool(result.get("success"))
    return out


def build_rows(baseline: dict[str, Any], hardened: dict[str, Any]) -> list[dict[str, Any]]:
    baseline_by_attack = baseline.get("by_attack_type") or {}
    hardened_by_attack = hardened.get("by_attack_type") or {}
    if not isinstance(baseline_by_attack, dict) or not isinstance(hardened_by_attack, dict):
        raise ValueError("Both reports must contain a by_attack_type object.")

    scenario = _challenge_name(baseline, hardened)
    rows: list[dict[str, Any]] = []

    for attack_family in sorted(set(baseline_by_attack) & set(hardened_by_attack)):
        baseline_data = baseline_by_attack.get(attack_family) or {}
        hardened_data = hardened_by_attack.get(attack_family) or {}
        if not isinstance(baseline_data, dict) or not isinstance(hardened_data, dict):
            continue

        baseline_success = _paired_asr(baseline_data)
        hardened_success = _paired_asr(hardened_data)
        paired_ids = sorted(set(baseline_success) & set(hardened_success))
        n = len(paired_ids)

        if n:
            baseline_asr = sum(baseline_success[sid] for sid in paired_ids) / n
            hardened_asr = sum(hardened_success[sid] for sid in paired_ids) / n
        else:
            baseline_n = int(baseline_data.get("valid_submission_attempts") or baseline_data.get("total_attempts") or 0)
            hardened_n = int(hardened_data.get("valid_submission_attempts") or hardened_data.get("total_attempts") or 0)
            n = min(baseline_n, hardened_n)
            baseline_asr = float(baseline_data.get("asr") or 0.0)
            hardened_asr = float(hardened_data.get("asr") or 0.0)

        rows.append(
            {
                "Scenario": scenario,
                "Attack family": attack_family,
                "Baseline ASR": baseline_asr,
                "Hardened ASR": hardened_asr,
                "Delta ASR": baseline_asr - hardened_asr,
                "n": n,
            }
        )

    return rows


def _format_pct(value: float) -> str:
    return f"{value:.1%}"


def write_csv(rows: list[dict[str, Any]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Scenario", "Attack family", "Baseline ASR", "Hardened ASR", "Delta ASR", "n"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_markdown(rows: list[dict[str, Any]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "| Scenario | Attack family | Baseline ASR | Hardened ASR | Delta ASR | n |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {scenario} | {attack} | {baseline} | {hardened} | {delta} | {n} |".format(
                scenario=row["Scenario"],
                attack=row["Attack family"],
                baseline=_format_pct(float(row["Baseline ASR"])),
                hardened=_format_pct(float(row["Hardened ASR"])),
                delta=_format_pct(float(row["Delta ASR"])),
                n=row["n"],
            )
        )
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare baseline and hardened source benchmark ASR reports.")
    parser.add_argument("--baseline", type=Path, required=True, help="Baseline source ASR report JSON.")
    parser.add_argument("--hardened", type=Path, required=True, help="Hardened source ASR report JSON.")
    parser.add_argument("--output-csv", type=Path, required=True, help="CSV table output path.")
    parser.add_argument("--output-md", type=Path, help="Optional Markdown table output path.")
    args = parser.parse_args()

    rows = build_rows(_load_json(args.baseline), _load_json(args.hardened))
    write_csv(rows, args.output_csv)
    if args.output_md:
        write_markdown(rows, args.output_md)

    print(f"Wrote {len(rows)} row(s) to {args.output_csv}")
    if args.output_md:
        print(f"Wrote Markdown table to {args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
