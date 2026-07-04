"""Shared repository paths for evaluation drivers."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EVALUATION_DIR = REPO_ROOT / "evaluation"
RESULTS_DIR = REPO_ROOT / "results"

EVAL_CONFIG_DIR = EVALUATION_DIR / "configs"
EVAL_DATA_DIR = EVALUATION_DIR / "data"

GROUND_TRUTH_PATH = EVAL_DATA_DIR / "ground_truth.json"
MODELS_CONFIG_PATH = EVAL_CONFIG_DIR / "models_config.yaml"

SAMPLE_SERVERS_DIR = REPO_ROOT / "sample_servers"
PITFALL_RESULTS_DIR = RESULTS_DIR / "pitfall_lab" / "user_servers"
EVAL_RESULTS_DIR = RESULTS_DIR / "evaluation"
SOURCE_BENCHMARK_RESULTS_DIR = RESULTS_DIR / "source_benchmark"
MULTI_MODEL_RESULTS_DIR = RESULTS_DIR / "multi_model_batch"
