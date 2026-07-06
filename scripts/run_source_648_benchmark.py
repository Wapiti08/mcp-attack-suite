#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import subprocess
import sys
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


CHALLENGES = ["emailsystem", "documentsystem", "ETHPriceServer"]
ATTACK_TYPES = ["tool_poisoning", "puppet", "multimodal_attack"]
TEMPLATE_SETS = {
    "singular": Path("environment/submissions/attacks/singular_attacks"),
    "compound": Path("environment/submissions/attacks/compound_attacks"),
}
MODEL_SUITES: dict[str, dict[str, list[str]]] = {
    "openai-mini": {
        "models": ["gpt-4o-mini", "gpt-4.1-mini"],
        "local_models": [],
    },
    "openai-broad": {
        "models": ["gpt-4o-mini", "gpt-4.1-mini", "gpt-4.1-nano", "gpt-4o"],
        "local_models": [],
    },
    "local-ollama": {
        "models": [],
        "local_models": [
            "llama3.1:8b@http://localhost:11434/v1",
            "llama3.2:3b@http://localhost:11434/v1",
            "qwen2.5:7b@http://localhost:11434/v1",
            "mistral:7b@http://localhost:11434/v1",
        ],
    },
    "local-lmstudio": {
        "models": [],
        "local_models": [
            "qwen/qwen3-8b@http://localhost:1234/v1",
            "meta-llama-3.1-8b-instruct@http://localhost:1234/v1",
            "mistral-7b-instruct@http://localhost:1234/v1",
        ],
    },
    "paper-smoke": {
        "models": ["gpt-4o-mini"],
        "local_models": ["llama3.1:8b@http://localhost:11434/v1"],
    },
}


@dataclass(frozen=True)
class ModelSpec:
    id: str
    provider: str = "default"
    base_url: str | None = None
    api_key: str | None = None

    @property
    def slug(self) -> str:
        value = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.id).strip("_")
        return value or "model"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_base_payload(challenge: str) -> str:
    path = repo_root() / "environment" / "arena" / "challenges" / challenge / "attacks" / "tool_poisoning.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    payload = str(data.get("tool_poisoning", {}).get("injection", "")).strip()
    if not payload:
        raise SystemExit(f"No tool_poisoning.injection found in {path}")
    return payload.replace("\\n", "\n")


def run_cmd(cmd: list[str], *, dry_run: bool, env: dict[str, str] | None = None) -> None:
    printable = shlex.join(cmd)
    if dry_run:
        prefix = ""
        if env:
            shown = {k: v for k, v in env.items() if k in {"OPENAI_MODEL", "OPENAI_BASE_URL"}}
            prefix = " ".join(f"{k}={shlex.quote(v)}" for k, v in shown.items())
            prefix = f"{prefix} " if prefix else ""
        print(prefix + printable)
        return
    print(f"\n$ {printable}")
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    subprocess.run(cmd, cwd=repo_root(), check=True, env=child_env)


def generate_submissions(
    *,
    challenge: str,
    template_set: str,
    templates_dir: Path,
    generated_root: Path,
    stamp: str,
    dry_run: bool,
) -> Path:
    base_payload = load_base_payload(challenge)
    cmd = [
        sys.executable,
        "scripts/gen_submissions.py",
        "--challenge",
        challenge,
        "--base-prompt",
        base_payload,
        "--templates-dir",
        str(templates_dir),
        "--out-dir",
        str(generated_root),
        "--stamp",
        f"{stamp}_{template_set}",
        "--no-compound",
    ]
    run_cmd(cmd, dry_run=dry_run)
    return generated_root / challenge / f"{stamp}_{template_set}"


def evaluate_submissions(
    *,
    challenge: str,
    template_set: str,
    submissions_dir: Path,
    results_root: Path,
    model: ModelSpec,
    num_runs: int,
    timeout: int,
    dry_run: bool,
    rerun_existing: bool,
) -> Path:
    output = results_root / model.slug / f"{challenge}_{template_set}.json"
    runs_dir = results_root / "run_artifacts" / model.slug / challenge / template_set
    if not rerun_existing and is_complete_result(output):
        print(f"[skip] existing complete result: {output}")
        return output
    cmd = [
        sys.executable,
        "-m",
        "evaluation.source_benchmark.evaluate_source_asr",
        "--challenge",
        challenge,
        "--submissions-dir",
        str(submissions_dir),
        "--attack-types",
        *ATTACK_TYPES,
        "--model",
        model.id,
        "--num-runs",
        str(num_runs),
        "--output",
        str(output),
        "--runs-dir",
        str(runs_dir),
        "--timeout",
        str(timeout),
    ]
    env = {
        "OPENAI_MODEL": model.id,
    }
    if model.base_url:
        env["OPENAI_BASE_URL"] = model.base_url
    if model.api_key is not None:
        env["OPENAI_API_KEY"] = model.api_key
    run_cmd(cmd, dry_run=dry_run, env=env)
    return output


def is_complete_result(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    by_attack = data.get("by_attack_type")
    if not isinstance(by_attack, dict):
        return False
    for attack_type in ATTACK_TYPES:
        report = by_attack.get(attack_type)
        if not isinstance(report, dict):
            return False
        if int(report.get("raw_run_errors", 0) or 0) > 0:
            return False
    return True


def summarize_result(path: Path, *, model: ModelSpec, template_set: str) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    meta = data.get("metadata", {})
    rows: list[dict[str, Any]] = []
    for attack_type, report in data.get("by_attack_type", {}).items():
        rows.append(
            {
                "challenge": meta.get("challenge", ""),
                "template_set": template_set,
                "attack_type": attack_type,
                "model_id": meta.get("model_id") or meta.get("model", model.id),
                "model_provider": model.provider,
                "model_base_url": model.base_url or "",
                "num_runs": int(meta.get("num_runs", report.get("num_runs", 0)) or 0),
                "timeout_seconds": int(meta.get("timeout_seconds", 0) or 0),
                "submissions": int(report.get("total_attempts", 0) or 0),
                "valid_submissions": int(report.get("valid_submission_attempts", report.get("total_attempts", 0)) or 0),
                "submission_errors": int(report.get("submission_errors", 0) or 0),
                "majority_successes": int(report.get("successful_attacks", 0) or 0),
                "submission_asr": float(report.get("asr", 0.0) or 0.0),
                "raw_run_attempts": int(report.get("raw_run_attempts", 0) or 0),
                "valid_raw_run_attempts": int(report.get("valid_raw_run_attempts", report.get("raw_run_attempts", 0)) or 0),
                "raw_run_successes": int(report.get("raw_run_successes", 0) or 0),
                "raw_run_errors": int(report.get("raw_run_errors", 0) or 0),
                "raw_run_asr": float(report.get("raw_run_asr", 0.0) or 0.0),
                "raw_run_completion_rate": float(report.get("raw_run_completion_rate", 1.0) or 0.0),
                "result_file": str(path),
            }
        )
    return rows


def write_aggregate(rows: list[dict[str, Any]], results_root: Path) -> None:
    total_submissions = sum(int(r["submissions"]) for r in rows)
    total_valid_submissions = sum(int(r["valid_submissions"]) for r in rows)
    total_submission_errors = sum(int(r["submission_errors"]) for r in rows)
    total_majority_successes = sum(int(r["majority_successes"]) for r in rows)
    total_raw_runs = sum(int(r["raw_run_attempts"]) for r in rows)
    total_valid_raw_runs = sum(int(r["valid_raw_run_attempts"]) for r in rows)
    total_raw_successes = sum(int(r["raw_run_successes"]) for r in rows)
    total_raw_errors = sum(int(r["raw_run_errors"]) for r in rows)

    aggregate = {
        "timestamp": datetime.now().isoformat(),
        "template_sets": sorted(TEMPLATE_SETS.keys()),
        "challenges": CHALLENGES,
        "attack_types": ATTACK_TYPES,
        "models": sorted({str(r["model_id"]) for r in rows}),
        "total_submissions": total_submissions,
        "total_valid_submissions": total_valid_submissions,
        "total_submission_errors": total_submission_errors,
        "total_majority_successes": total_majority_successes,
        "submission_asr": total_majority_successes / total_valid_submissions if total_valid_submissions else 0.0,
        "total_raw_run_attempts": total_raw_runs,
        "total_valid_raw_run_attempts": total_valid_raw_runs,
        "total_raw_run_successes": total_raw_successes,
        "total_raw_run_errors": total_raw_errors,
        "raw_run_asr": total_raw_successes / total_valid_raw_runs if total_valid_raw_runs else 0.0,
        "raw_run_completion_rate": total_valid_raw_runs / total_raw_runs if total_raw_runs else 0.0,
        "rows": rows,
    }

    results_root.mkdir(parents=True, exist_ok=True)
    (results_root / "aggregate_648.json").write_text(json.dumps(aggregate, indent=2), encoding="utf-8")

    csv_path = results_root / "aggregate_648.csv"
    fieldnames = [
        "challenge",
        "template_set",
        "attack_type",
        "model_id",
        "model_provider",
        "model_base_url",
        "num_runs",
        "timeout_seconds",
        "submissions",
        "valid_submissions",
        "submission_errors",
        "majority_successes",
        "submission_asr",
        "raw_run_attempts",
        "valid_raw_run_attempts",
        "raw_run_successes",
        "raw_run_errors",
        "raw_run_asr",
        "raw_run_completion_rate",
        "result_file",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved aggregate JSON: {results_root / 'aggregate_648.json'}")
    print(f"Saved aggregate CSV:  {csv_path}")
    print(f"Raw runs completed: {total_valid_raw_runs}/{total_raw_runs}")
    print(f"Raw run errors: {total_raw_errors}")
    print(f"Raw runs successful: {total_raw_successes}/{total_valid_raw_runs}")
    print(f"Raw run ASR: {aggregate['raw_run_asr']:.1%}")
    print(f"Raw run completion: {aggregate['raw_run_completion_rate']:.1%}")


def parse_model_arg(value: str, *, provider: str = "default", default_base_url: str | None = None) -> ModelSpec:
    """
    Parse MODEL or MODEL@BASE_URL or MODEL@BASE_URL@API_KEY.

    Local OpenAI-compatible servers usually ignore the API key, but the OpenAI SDK
    still expects one. If a local base URL is provided without a key, use "local".
    """
    parts = value.split("@")
    model_id = parts[0].strip()
    if not model_id:
        raise SystemExit(f"Invalid model spec: {value!r}")
    base_url = parts[1].strip() if len(parts) >= 2 and parts[1].strip() else default_base_url
    api_key = parts[2].strip() if len(parts) >= 3 and parts[2].strip() else None
    if base_url and api_key is None:
        api_key = "local"
    return ModelSpec(id=model_id, provider=provider, base_url=base_url, api_key=api_key)


def parse_models(args: argparse.Namespace) -> list[ModelSpec]:
    suite_models: list[str] = []
    suite_local_models: list[str] = []
    for suite in args.model_suite:
        if suite not in MODEL_SUITES:
            known = ", ".join(sorted(MODEL_SUITES))
            raise SystemExit(f"Unknown model suite {suite!r}. Known suites: {known}")
        suite_models.extend(MODEL_SUITES[suite].get("models", []))
        suite_local_models.extend(MODEL_SUITES[suite].get("local_models", []))

    specs: list[ModelSpec] = []
    for value in [*suite_models, *args.models]:
        specs.append(parse_model_arg(value, provider="default"))
    for value in [*suite_local_models, *args.local_models]:
        specs.append(parse_model_arg(value, provider="local", default_base_url=args.local_base_url))
    if not specs:
        specs.append(ModelSpec(id=args.model))
    deduped: dict[tuple[str, str | None], ModelSpec] = {}
    for spec in specs:
        deduped[(spec.id, spec.base_url)] = spec
    return list(deduped.values())


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and evaluate the 648-run source benchmark.")
    parser.add_argument("--model", default="gpt-4o-mini", help="Model id/version to evaluate.")
    parser.add_argument(
        "--model-suite",
        nargs="+",
        default=[],
        choices=sorted(MODEL_SUITES.keys()),
        help="Named model suite(s) to expand before --models/--local-models.",
    )
    parser.add_argument(
        "--list-model-suites",
        action="store_true",
        help="Print available model suites and exit.",
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=[],
        help=(
            "Model ids to compare on the current/default endpoint. "
            "Each item may be MODEL, MODEL@BASE_URL, or MODEL@BASE_URL@API_KEY."
        ),
    )
    parser.add_argument(
        "--local-models",
        nargs="+",
        default=[],
        help=(
            "Local OpenAI-compatible model ids to compare. "
            "Each item may be MODEL or MODEL@BASE_URL. API key defaults to 'local'."
        ),
    )
    parser.add_argument(
        "--local-base-url",
        default="http://localhost:1234/v1",
        help="Default base URL for --local-models, e.g. LM Studio/vLLM. For Ollama use http://localhost:11434/v1.",
    )
    parser.add_argument("--num-runs", type=int, default=3, help="Runs per submission.")
    parser.add_argument("--timeout", type=int, default=300, help="Seconds per runner invocation before timeout.")
    parser.add_argument("--stamp", default="paper_648", help="Submission folder stamp prefix.")
    parser.add_argument(
        "--generated-root",
        type=Path,
        default=Path("environment/submissions/generated"),
        help="Root for generated submissions.",
    )
    parser.add_argument(
        "--results-root",
        type=Path,
        default=Path("results/source_benchmark/paper_648"),
        help="Root for result JSON/CSV and run artifacts.",
    )
    parser.add_argument("--skip-generate", action="store_true", help="Use existing generated submissions.")
    parser.add_argument(
        "--generate-missing",
        action="store_true",
        help="With --skip-generate, generate only missing submission directories before evaluation.",
    )
    parser.add_argument("--skip-eval", action="store_true", help="Only generate submissions.")
    parser.add_argument(
        "--rerun-existing",
        action="store_true",
        help="Rerun evaluations even when the output JSON already exists and looks complete.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")
    args = parser.parse_args()

    if args.list_model_suites:
        print("Available model suites:")
        for name, suite in sorted(MODEL_SUITES.items()):
            models = suite.get("models", [])
            local_models = suite.get("local_models", [])
            print(f"\n{name}")
            if models:
                print("  cloud/default endpoint:")
                for model in models:
                    print(f"    - {model}")
            if local_models:
                print("  local OpenAI-compatible:")
                for model in local_models:
                    print(f"    - {model}")
        return 0

    models = parse_models(args)
    print("Models:")
    for model in models:
        endpoint = model.base_url or "<environment/default>"
        print(f"  - {model.id} [{model.provider}] endpoint={endpoint}")

    submissions_by_pair: dict[tuple[str, str], Path] = {}
    missing_submissions: list[Path] = []
    for challenge in CHALLENGES:
        for template_set, templates_dir in TEMPLATE_SETS.items():
            submissions_dir = args.generated_root / challenge / f"{args.stamp}_{template_set}"
            should_generate = not args.skip_generate or (args.generate_missing and not submissions_dir.exists())
            if should_generate:
                submissions_dir = generate_submissions(
                    challenge=challenge,
                    template_set=template_set,
                    templates_dir=templates_dir,
                    generated_root=args.generated_root,
                    stamp=args.stamp,
                    dry_run=args.dry_run,
                )
            elif not submissions_dir.exists():
                missing_submissions.append(submissions_dir)
            submissions_by_pair[(challenge, template_set)] = submissions_dir

    if missing_submissions and not args.skip_eval:
        print("\nMissing generated submission directories:")
        for path in missing_submissions:
            print(f"  - {path}")
        print("\nGenerate them first, or rerun with --generate-missing, or omit --skip-generate.")
        return 1

    output_files: list[tuple[ModelSpec, str, Path]] = []
    if not args.skip_eval:
        for model in models:
            for challenge in CHALLENGES:
                for template_set in TEMPLATE_SETS:
                    output = evaluate_submissions(
                        challenge=challenge,
                        template_set=template_set,
                        submissions_dir=submissions_by_pair[(challenge, template_set)],
                        results_root=args.results_root,
                        model=model,
                        num_runs=args.num_runs,
                        timeout=args.timeout,
                        dry_run=args.dry_run,
                        rerun_existing=args.rerun_existing,
                    )
                    output_files.append((model, template_set, output))

    if args.dry_run or args.skip_eval:
        return 0

    rows: list[dict[str, Any]] = []
    for model, template_set, output in output_files:
        rows.extend(summarize_result(output, model=model, template_set=template_set))
    write_aggregate(rows, args.results_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
