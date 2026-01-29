from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import logging

from openai.types.chat import (
    ChatCompletionAssistantMessageParam,
    ChatCompletionMessage,
    ChatCompletionMessageParam,
    ChatCompletionMessageToolCallParam,
    ChatCompletionToolParam,
)

from clientbuild.logging_setup import safe_json_dumps, summarize_message


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]

    def to_openai_tool(self) -> ChatCompletionToolParam:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass(frozen=True)
class Action:
    pass


@dataclass(frozen=True)
class Query(Action):
    messages: list[ChatCompletionMessageParam]
    tools: list[ChatCompletionToolParam]


@dataclass(frozen=True)
class ToolCall(Action):
    id: str
    name: str
    arguments: str


@dataclass(frozen=True)
class Response(Action):
    response: str


class Planner(ABC):
    @abstractmethod
    def next_action(self, message: ChatCompletionMessage | ChatCompletionMessageParam) -> Action:
        pass


class BasicPlanner(Planner):
    """
    A direct port of Tutorial.ipynb's BasicPlanner:
    - user/tool message -> Query(model, tools)
    - assistant tool_call -> ToolCall(...)
    - assistant content -> Response(...)
    """

    def __init__(self, state: list[ChatCompletionMessageParam], tools: list[ToolSpec]):
        self.tools = tools
        self.history = state
        self._logger = logging.getLogger(__name__)
        self._log_max_payload_chars = 20000
        self._log_max_message_chars = 4000

    def next_action(self, message: ChatCompletionMessage | ChatCompletionMessageParam) -> Action:
        self._logger.info(
            "planner.next_action input=%s",
            safe_json_dumps(
                summarize_message(message, max_chars=self._log_max_message_chars),
                max_chars=self._log_max_message_chars,
            ),
        )
        match message:
            case {"role": "user"} | {"role": "tool"}:
                self.history.append(message)
                action = Query(
                    messages=self.history,
                    tools=[tool.to_openai_tool() for tool in self.tools],
                )
                self._logger.info(
                    "planner.next_action output=Query messages=%d tools=%d",
                    len(action.messages),
                    len(action.tools),
                )
                return action

            case ChatCompletionMessage(role="assistant", content=content, tool_calls=tool_calls) if tool_calls:
                assert len(tool_calls) == 1, "Only one tool call is supported"
                tool_calls_param: list[ChatCompletionMessageToolCallParam] = [
                    {
                        "id": tool_call.id,
                        "function": {
                            "name": tool_call.function.name,
                            "arguments": tool_call.function.arguments,
                        },
                        "type": "function",
                    }
                    for tool_call in tool_calls
                ]
                self.history.append(
                    ChatCompletionAssistantMessageParam(
                        role="assistant",
                        content=content,
                        tool_calls=tool_calls_param,
                    )
                )
                action = ToolCall(
                    id=tool_calls[0].id,
                    name=tool_calls[0].function.name,
                    arguments=tool_calls[0].function.arguments,
                )
                self._logger.info(
                    "planner.next_action output=ToolCall id=%s name=%s arguments=%s",
                    action.id,
                    action.name,
                    action.arguments,
                )
                return action

            case ChatCompletionMessage(role="assistant", content=content, tool_calls=tool_calls) if content:
                assert not tool_calls, "Tool calls are not supported in this context"
                self.history.append(
                    ChatCompletionAssistantMessageParam(role="assistant", content=content, tool_calls=[])
                )
                action = Response(response=content)
                self._logger.info("planner.next_action output=Response len=%d", len(content or ""))
                return action

            case _:
                raise ValueError(f"Invalid message format: {message!r}")
