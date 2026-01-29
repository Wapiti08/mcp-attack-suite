from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
import logging
from typing import Any, Callable, Sequence

from openai.types.chat import ChatCompletionMessage, ChatCompletionMessageParam, ChatCompletionToolMessageParam

from environment.clientbuild.mcp_hub import MCPHub
from environment.clientbuild.planner import Planner, Query, Response, ToolCall
from environment.clientbuild.logging_setup import safe_json_dumps, summarize_message


@dataclass(frozen=True)
class TraceEvent:
    turn: int
    action: Any


Policy = Callable[[Sequence[TraceEvent]], None]


class PlanningLoop:
    def __init__(
        self,
        *,
        planner: Planner,
        client: Any,
        model: str,
        mcp_hub: MCPHub,
        policy: Policy | None = None,
        trace_callback: Callable[[dict[str, Any]], None] | None = None,
        max_turns: int = 32,
        log_max_payload_chars: int = 20000,
        log_max_message_chars: int = 4000,
    ):
        self.planner = planner
        self.client = client
        self.model = model
        self.mcp_hub = mcp_hub
        self.policy = policy
        self.trace_callback = trace_callback
        self.max_turns = max_turns
        self.turn = 0
        self._logger = logging.getLogger(__name__)
        self._log_max_payload_chars = log_max_payload_chars
        self._log_max_message_chars = log_max_message_chars

    def _trace(self, event: dict[str, Any]) -> None:
        if self.trace_callback is None:
            return
        try:
            self.trace_callback(dict(event))
        except Exception:
            return

    async def _create_chat_completion(self, messages: list[ChatCompletionMessageParam], tools: list[dict[str, Any]]):
        create = self.client.chat.completions.create
        kwargs = dict(model=self.model, messages=messages, tools=tools, parallel_tool_calls=False)
        tool_names = [t.get("function", {}).get("name") for t in tools]
        self._trace(
            {
                "event": "llm.request",
                "turn": self.turn,
                "model": self.model,
                "messages_count": len(messages),
                "tools_count": len(tools),
                "tools": tool_names,
                # keep it readable: last few messages only
                "messages_tail": [summarize_message(m, max_chars=400) for m in messages[-6:]],
            }
        )
        self._logger.info(
            "loop.llm_request model=%s messages=%d tools=%d last=%s",
            self.model,
            len(messages),
            len(tools),
            safe_json_dumps(
                summarize_message(messages[-1], max_chars=self._log_max_message_chars) if messages else None,
                max_chars=self._log_max_message_chars,
            ),
        )
        self._logger.debug(
            "loop.llm_request messages_payload=%s",
            safe_json_dumps(messages, max_chars=self._log_max_payload_chars),
        )
        self._logger.debug(
            "loop.llm_request tools_payload=%s",
            safe_json_dumps([t.get("function", {}).get("name") for t in tools], max_chars=self._log_max_payload_chars),
        )
        result = create(**kwargs)
        if inspect.isawaitable(result):
            resp = await result
        else:
            resp = result
        try:
            msg = resp.choices[0].message
            self._trace(
                {
                    "event": "llm.response",
                    "turn": self.turn,
                    "model": self.model,
                    "message": summarize_message(msg, max_chars=1200),
                }
            )
            self._logger.info(
                "loop.llm_response message=%s",
                safe_json_dumps(
                    summarize_message(msg, max_chars=self._log_max_message_chars),
                    max_chars=self._log_max_message_chars,
                ),
            )
            self._logger.debug(
                "loop.llm_response raw=%s",
                safe_json_dumps(resp.model_dump(), max_chars=self._log_max_payload_chars),
            )
        except Exception:
            self._logger.debug("loop.llm_response raw=%r", resp)
        return resp

    async def loop(self, msg: ChatCompletionMessage | ChatCompletionMessageParam) -> str:
        current_msg: ChatCompletionMessage | ChatCompletionMessageParam = msg
        trace: list[TraceEvent] = []

        while True:
            self.turn += 1
            if self.turn > self.max_turns:
                raise RuntimeError(f"Exceeded max_turns={self.max_turns}")

            self._logger.info(
                "loop.turn start=%d current=%s",
                self.turn,
                safe_json_dumps(
                    summarize_message(current_msg, max_chars=self._log_max_message_chars),
                    max_chars=self._log_max_message_chars,
                ),
            )
            action = self.planner.next_action(current_msg)
            trace.append(TraceEvent(turn=self.turn, action=action))
            if self.policy is not None:
                self.policy(trace)

            match action:
                case Query(messages, tools):
                    self._logger.info(
                        "loop.action Query turn=%d messages=%d tools=%d",
                        self.turn,
                        len(messages),
                        len(tools),
                    )
                    response = await self._create_chat_completion(messages=messages, tools=tools)
                    current_msg = response.choices[0].message

                case ToolCall(id, name, arguments):
                    self._logger.info(
                        "loop.action ToolCall turn=%d id=%s name=%s arguments=%s",
                        self.turn,
                        id,
                        name,
                        arguments,
                    )
                    args_dict = json.loads(arguments) if arguments else {}
                    self._trace({"event": "llm.tool_call", "turn": self.turn, "name": name, "args": args_dict, "tool_call_id": id})
                    result = await self.mcp_hub.call_tool(name, args_dict)
                    self._logger.info("loop.tool_result turn=%d id=%s name=%s result=%r", self.turn, id, name, result)
                    current_msg = ChatCompletionToolMessageParam(
                        role="tool",
                        tool_call_id=id,
                        content=str(result),
                    )

                case Response(response):
                    self._logger.info("loop.action Response turn=%d len=%d", self.turn, len(response or ""))
                    self._logger.debug(
                        "loop.final_response payload=%s",
                        safe_json_dumps(response, max_chars=self._log_max_payload_chars),
                    )
                    return response

                case _:
                    raise ValueError(f"Invalid action: {action!r}")
