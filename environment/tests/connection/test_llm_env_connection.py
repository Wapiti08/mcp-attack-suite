from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse
import socket
import time


def _ensure_import_paths() -> None:
    # environment/tests/connection/test_*.py -> parents[2] == environment/, parents[3] == repo root
    repo_root = Path(__file__).resolve().parents[3]
    env_root = Path(__file__).resolve().parents[2]
    attackmethods_root = env_root / "attackmethodsCollection"
    for p in (repo_root, env_root, attackmethods_root):
        sp = str(p)
        if sp not in sys.path:
            sys.path.insert(0, sp)


class TestLLMEnvConnection(unittest.TestCase):
    """
    Integration test: verifies the LLM configured in `environment/.env` can answer a single chat completion.

    Default behavior is to SKIP unless you opt in:
      RUN_LLM_CONNECTION_TEST=1 python -m unittest environment/tests/connection/test_llm_env_connection.py
    """

    def test_llm_chat_completion(self) -> None:
        if os.getenv("RUN_LLM_CONNECTION_TEST") != "1":
            raise unittest.SkipTest("Set RUN_LLM_CONNECTION_TEST=1 to run the real LLM connectivity test.")

        _ensure_import_paths()
        from clientbuild.settings import load_settings  # type: ignore
        from openai import OpenAI  # type: ignore
        from openai import APIConnectionError  # type: ignore

        settings = load_settings()

        if settings.base_url:
            parsed = urlparse(settings.base_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            deadline = time.time() + 2.0
            last_err: OSError | None = None
            while time.time() < deadline:
                try:
                    with socket.create_connection((host, port), timeout=0.5):
                        last_err = None
                        break
                except OSError as e:
                    last_err = e
                    time.sleep(0.1)
            if last_err is not None:
                self.fail(
                    "Cannot connect to OPENAI_BASE_URL "
                    f"({settings.base_url} -> {host}:{port}): {last_err}. "
                    "Start your local OpenAI-compatible server (e.g., LM Studio) or fix `environment/.env`."
                )

        client = OpenAI(
            api_key=settings.api_key,
            base_url=settings.base_url,
            timeout=15.0,
            max_retries=0,
        )

        try:
            resp = client.chat.completions.create(
                model=settings.model,
                messages=[
                    {"role": "system", "content": "You are a connectivity test. Reply briefly."},
                    {"role": "user", "content": "ping"},
                ],
                max_tokens=16,
                temperature=0,
            )
        except APIConnectionError as e:
            self.fail(
                f"OpenAI client connection failed (base_url={settings.base_url!r}, model={settings.model!r}): {e}"
            )

        content = (resp.choices[0].message.content or "").strip()
        self.assertTrue(content, "LLM returned empty content (check OPENAI_* in environment/.env and the server status).")


if __name__ == "__main__":
    unittest.main()
