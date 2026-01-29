from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass
import logging
from typing import Any, Iterable, Mapping

from clientbuild.logging_setup import safe_json_dumps
from clientbuild.planner import ToolSpec


@dataclass(frozen=True)
class MCPToolRef:
    server_name: str
    tool_name: str


def _get_attr_or_key(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _extract_tool_fields(raw_tool: Any) -> tuple[str, str, dict[str, Any] | None]:
    name = (
        _get_attr_or_key(raw_tool, "name")
        or _get_attr_or_key(raw_tool, "tool_name")
        or _get_attr_or_key(raw_tool, "id")
    )
    if not isinstance(name, str) or not name:
        raise ValueError(f"Invalid MCP tool name: {name!r}")

    description = (
        _get_attr_or_key(raw_tool, "description")
        or _get_attr_or_key(raw_tool, "doc")
        or _get_attr_or_key(raw_tool, "documentation")
        or ""
    )
    if not isinstance(description, str):
        description = str(description)

    schema = (
        _get_attr_or_key(raw_tool, "inputSchema")
        or _get_attr_or_key(raw_tool, "input_schema")
        or _get_attr_or_key(raw_tool, "parameters")
    )
    if schema is not None and not isinstance(schema, dict):
        schema = None

    return name, description, schema


def _normalize_parameters_schema(schema: dict[str, Any] | None) -> dict[str, Any]:
    if schema is None:
        return {"type": "object", "properties": {}}
    if schema.get("type") is None:
        schema = dict(schema)
        schema["type"] = "object"
    schema.setdefault("properties", {})
    return schema


class MCPHub:
    """
    Manages one-to-one FastMCP clients, aggregates their tool sets, and routes calls.

    Tool names are exposed to the planner as:
    - the raw MCP tool name when unique across all servers
    - otherwise: \"{server_name}__{tool_name}\"
    """

    def __init__(self, servers: list[tuple[str, Any]]):
        self._servers = servers
        self._stack: AsyncExitStack | None = None
        self._tool_specs: list[ToolSpec] = []
        self._tool_map: dict[str, MCPToolRef] = {}
        self._logger = logging.getLogger(__name__)

    @classmethod
    def from_urls(cls, urls: Iterable[str], *, server_names: Iterable[str] | None = None) -> "MCPHub":
        try:
            from fastmcp import Client as FastMCPClient  # type: ignore
        except Exception as e:  # pragma: no cover - depends on local env
            raise RuntimeError(
                "fastmcp is required to connect to MCP servers. Install it first (e.g. `pip install fastmcp`)."
            ) from e

        urls_list = list(urls)
        if server_names is None:
            names = [f"mcp{i+1}" for i in range(len(urls_list))]
        else:
            names = list(server_names)
            if len(names) != len(urls_list):
                raise ValueError("server_names length must match urls length")

        servers: list[tuple[str, Any]] = []
        for name, url in zip(names, urls_list, strict=True):
            servers.append((name, FastMCPClient(url)))
        return cls(servers)

    async def __aenter__(self) -> "MCPHub":
        self._stack = AsyncExitStack()
        self._logger.info("mcp_hub.connect servers=%s", [name for name, _ in self._servers])
        for _, client in self._servers:
            await self._stack.enter_async_context(client)
        await self.refresh_tools()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None

    @property
    def tool_specs(self) -> list[ToolSpec]:
        return list(self._tool_specs)

    def resolve_tool(self, exposed_name: str) -> MCPToolRef:
        if exposed_name not in self._tool_map:
            raise KeyError(f"Unknown tool: {exposed_name}")
        return self._tool_map[exposed_name]

    async def refresh_tools(self) -> None:
        self._logger.info("mcp_hub.refresh_tools start")
        tool_lists = await asyncio.gather(*[client.list_tools() for _, client in self._servers])

        raw_by_server: list[tuple[str, list[Any]]] = []
        for (server_name, _), tools in zip(self._servers, tool_lists, strict=True):
            raw_by_server.append((server_name, list(tools or [])))

        base_names: dict[str, int] = {}
        extracted: list[tuple[str, str, str, dict[str, Any]]] = []
        for server_name, raw_tools in raw_by_server:
            for raw_tool in raw_tools:
                tool_name, tool_desc, tool_schema = _extract_tool_fields(raw_tool)
                base_names[tool_name] = base_names.get(tool_name, 0) + 1
                extracted.append(
                    (
                        server_name,
                        tool_name,
                        tool_desc,
                        _normalize_parameters_schema(tool_schema),
                    )
                )

        tool_specs: list[ToolSpec] = []
        tool_map: dict[str, MCPToolRef] = {}

        for server_name, tool_name, tool_desc, params in extracted:
            if base_names.get(tool_name, 0) > 1:
                exposed = f"{server_name}__{tool_name}"
                desc = f"[server: {server_name}] {tool_desc}".strip()
            else:
                exposed = tool_name
                desc = tool_desc

            tool_specs.append(ToolSpec(name=exposed, description=desc, parameters=params))
            tool_map[exposed] = MCPToolRef(server_name=server_name, tool_name=tool_name)

        self._tool_specs = tool_specs
        self._tool_map = tool_map
        self._logger.info("mcp_hub.refresh_tools done tools=%d", len(self._tool_specs))

    async def call_tool(self, exposed_name: str, arguments: Mapping[str, Any]) -> Any:
        ref = self.resolve_tool(exposed_name)
        self._logger.info(
            "mcp_hub.call_tool exposed=%s server=%s tool=%s args=%s",
            exposed_name,
            ref.server_name,
            ref.tool_name,
            safe_json_dumps(dict(arguments), max_chars=20000),
        )
        for server_name, client in self._servers:
            if server_name == ref.server_name:
                result = await client.call_tool(ref.tool_name, dict(arguments))
                self._logger.info(
                    "mcp_hub.call_tool result exposed=%s server=%s tool=%s result=%r",
                    exposed_name,
                    ref.server_name,
                    ref.tool_name,
                    safe_json_dumps(result, max_chars=20000),
                )
                return result
        raise RuntimeError(f"Server not found for tool: {exposed_name}")
