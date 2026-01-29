from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Ensure repo root is importable so `environment.clientbuild.*` works reliably.
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from environment.clientbuild.loop import PlanningLoop
from environment.clientbuild.mcp_hub import MCPHub
from environment.clientbuild.planner import BasicPlanner
from environment.clientbuild.settings import load_settings
from environment.clientbuild.logging_setup import LoggingConfig, setup_logging


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mcp", action="append", default=None)
    parser.add_argument("--prompt", default="成都现在天气怎么样？如果需要，调用合适的工具。")
    args = parser.parse_args()

    settings = load_settings()
    _, log_path = setup_logging(
        LoggingConfig(
            enabled=settings.log_enabled,
            level=settings.log_level,
            log_dir=settings.log_dir,
            run_name="clientbuild",
            max_payload_chars=settings.log_max_payload_chars,
            max_message_chars=settings.log_max_message_chars,
        )
    )
    if log_path:
        print(f"[log] {log_path}")
    mcp_urls = args.mcp if args.mcp else settings.mcp_urls

    async with MCPHub.from_urls(mcp_urls, server_names=settings.mcp_names if args.mcp is None else None) as hub:
        planner = BasicPlanner(
            state=[
                {
                    "role": "system",
                    "content": "你是一个会使用工具的助手。必要时调用工具，并在得到工具结果后给出最终回答。",
                }
            ],
            tools=hub.tool_specs,
        )
        loop = PlanningLoop(
            planner=planner,
            client=settings.openai_async_client(),
            model=settings.model,
            mcp_hub=hub,
            log_max_payload_chars=settings.log_max_payload_chars,
            log_max_message_chars=settings.log_max_message_chars,
        )
        result = await loop.loop({"role": "user", "content": args.prompt})
        print(result)


if __name__ == "__main__":
    asyncio.run(main())
