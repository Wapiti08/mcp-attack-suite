from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any


def _sanitize_filename(name: str) -> str:
    name = name.strip().replace(" ", "_")
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", name)
    return name or "run"


def truncate(text: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def safe_json_dumps(obj: Any, *, max_chars: int = 5000) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        s = str(obj)
    return truncate(s, max_chars=max_chars)


def summarize_message(msg: Any, *, max_chars: int = 2000) -> dict[str, Any]:
    if isinstance(msg, dict):
        role = msg.get("role")
        content = msg.get("content")
        tool_call_id = msg.get("tool_call_id") or msg.get("tool_callId")
        tool_calls = msg.get("tool_calls")
        return {
            "role": role,
            "content": truncate(str(content), max_chars=max_chars) if content is not None else None,
            "tool_call_id": tool_call_id,
            "tool_calls": tool_calls,
        }

    role = getattr(msg, "role", None)
    content = getattr(msg, "content", None)
    tool_calls = getattr(msg, "tool_calls", None)
    return {
        "role": role,
        "content": truncate(str(content), max_chars=max_chars) if content is not None else None,
        "tool_calls": tool_calls,
    }


@dataclass(frozen=True)
class LoggingConfig:
    enabled: bool = True
    level: str = "DEBUG"
    log_dir: str = "environment/clientbuild/logs"
    run_name: str = "run"
    max_payload_chars: int = 10000
    max_message_chars: int = 2000
    console_enabled: bool = True
    console_level: str = "INFO"


def setup_logging(cfg: LoggingConfig) -> tuple[logging.Logger, str | None]:
    """
    Configure Python logging for this project. Returns (root_logger, log_path).
    """
    root_logger = logging.getLogger()
    if not cfg.enabled:
        root_logger.handlers.clear()
        root_logger.setLevel(logging.CRITICAL + 1)
        return root_logger, None

    level = getattr(logging, cfg.level.upper(), logging.DEBUG)
    root_logger.setLevel(level)

    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    os.makedirs(cfg.log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{_sanitize_filename(cfg.run_name)}_{timestamp}.log"
    log_path = os.path.join(cfg.log_dir, filename)

    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    if cfg.console_enabled:
        console_level = getattr(logging, str(cfg.console_level).upper(), logging.INFO)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    # Reduce noise from common libraries unless explicitly enabled elsewhere.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    return root_logger, log_path
