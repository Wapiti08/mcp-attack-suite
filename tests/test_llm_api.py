#!/usr/bin/env python3
"""
Minimal LLM API connectivity test (OpenAI-compatible).

Reads config from `.env` if present:
  - OPENAI_API_KEY (required)
  - OPENAI_MODEL (required)
  - OPENAI_BASE_URL (optional, e.g. http://localhost:1234/v1/)

Usage:
  python3 test_llm_api.py
  python3 test_llm_api.py --prompt "Hello"
  python3 test_llm_api.py --base-url http://localhost:1234/v1/ --model meta-llama-3.1-8b-instruct --api-key local
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Optional


def _load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception:
        return
    load_dotenv()


def _required(name: str, value: Optional[str]) -> str:
    if value:
        return value
    raise SystemExit(f"Missing required config: {name} (set env or pass flag)")


def _print_err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _run_new_sdk(base_url: Optional[str], api_key: str, model: str, prompt: str) -> str:
    from openai import OpenAI  # type: ignore

    client_kwargs: dict[str, Any] = {"api_key": api_key}
    if base_url:
        client_kwargs["base_url"] = base_url
    client = OpenAI(**client_kwargs)

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""


def _run_legacy_sdk(base_url: Optional[str], api_key: str, model: str, prompt: str) -> str:
    import openai  # type: ignore

    openai.api_key = api_key
    if base_url:
        openai.api_base = base_url

    resp = openai.ChatCompletion.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp["choices"][0]["message"]["content"]


def main() -> int:
    _load_dotenv_if_available()

    p = argparse.ArgumentParser(description="Test an OpenAI-compatible LLM API with a single chat completion.")
    p.add_argument("--prompt", default="ping", help="User prompt to send")
    p.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL"), help="Override OPENAI_BASE_URL")
    p.add_argument("--model", default=os.getenv("OPENAI_MODEL"), help="Override OPENAI_MODEL")
    p.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY"), help="Override OPENAI_API_KEY")
    ns = p.parse_args()

    api_key = _required("OPENAI_API_KEY/--api-key", ns.api_key)
    model = _required("OPENAI_MODEL/--model", ns.model)
    base_url = ns.base_url

    try:
        text = _run_new_sdk(base_url, api_key, model, ns.prompt)
    except Exception as e_new:
        try:
            text = _run_legacy_sdk(base_url, api_key, model, ns.prompt)
        except Exception as e_old:
            _print_err(f"ERROR: openai SDK call failed (new SDK error: {e_new}; legacy SDK error: {e_old})")
            return 1

    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

