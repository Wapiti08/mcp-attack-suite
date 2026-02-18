from __future__ import annotations

import asyncio
import json
import os
import random
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
import inspect
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
import socket

from .validate import validate_objective


def env_root() -> Path:
    # environment/arena/runner/run.py -> parents[2] == environment/
    return Path(__file__).resolve().parents[2]


def repo_root() -> Path:
    # environment/... -> parents[3] == repo root
    return Path(__file__).resolve().parents[3]


def _ensure_import_paths() -> None:
    root = repo_root()
    env = env_root()
    for p in (root, env):
        sp = str(p)
        if sp not in sys.path:
            sys.path.insert(0, sp)


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Expected object JSON: {path}")
    return raw


def _substitute_submission_placeholders(value: Any, *, submission_path: Path) -> Any:
    """
    Recursively replace "$SUBMISSION" placeholders with the artifact path.
    Used by attack configs that refer to the provided artifact file.
    """
    if isinstance(value, str):
        if value in {"$SUBMISSION", "${SUBMISSION}"}:
            return str(submission_path.resolve())
        return value
    if isinstance(value, list):
        return [_substitute_submission_placeholders(v, submission_path=submission_path) for v in value]
    if isinstance(value, dict):
        return {k: _substitute_submission_placeholders(v, submission_path=submission_path) for k, v in value.items()}
    return value


def _resolve_submission_input(*, submission: str, attack_type: str) -> tuple[Path | None, str | None]:
    """
    Interpret the CLI `--submission` value.

    - Usually it's a filesystem path to a submission artifact.
    - For `attack_type="tool_poisoning"`, it may also be a raw injection string; in that case we
      return (None, injection_override).
    """
    raw = str(submission or "")
    if not raw.strip():
        raise ValueError("Empty --submission value.")

    candidate = Path(raw)
    if candidate.exists():
        return candidate, None

    # Not a path on disk: only allowed for tool poisoning injection overrides.
    if str(attack_type) == "tool_poisoning":
        return None, raw

    raise SystemExit(f"Submission file not found: {candidate}")


def _pick_reasonable_port() -> int:
    # Avoid privileged ports and common dev ports. This is "best effort" without probing.
    return random.randint(20000, 50000)


def _wait_tcp(url: str, *, timeout_s: float = 10.0) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    deadline = time.time() + timeout_s
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except PermissionError:
            # If sockets are forbidden, the runner cannot function (it needs to talk to local MCP servers).
            raise RuntimeError(
                "Socket connections are not permitted in this environment; cannot connect to local MCP servers. "
                f"Failed while probing {host}:{port} ({url})."
            )
        except OSError as e:
            last_err = e
            time.sleep(0.15)
    raise RuntimeError(f"Timed out waiting for {host}:{port} ({url}): {last_err}")


@dataclass(frozen=True)
class SpawnedServer:
    name: str
    url: str
    module: str
    proc: subprocess.Popen


def _spawn_python_module(
    *,
    name: str,
    module: str,
    host: str,
    port: int,
    url_template: str,
    stdout: Any = None,
    stderr: Any = None,
    extra_env: dict[str, str] | None = None,
) -> SpawnedServer:
    if port == 0:
        port = _pick_reasonable_port()
    url = str(url_template).format(host=host, port=port)
    root = repo_root()
    env_root_path = env_root()
    env = dict(os.environ)
    existing_pp = env.get("PYTHONPATH", "")
    prefix = os.pathsep.join([str(root), str(env_root_path)])
    env["PYTHONPATH"] = prefix + (os.pathsep + existing_pp if existing_pp else "")
    if extra_env:
        for k, v in extra_env.items():
            if k and v is not None:
                env[str(k)] = str(v)
    proc = subprocess.Popen(
        [sys.executable, "-m", module, "--host", host, "--port", str(port)],
        env=env,
        stdout=stdout,
        stderr=stderr,
        text=True,
    )
    try:
        _wait_tcp(url, timeout_s=10.0)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
        raise
    return SpawnedServer(name=name, url=url, module=module, proc=proc)


def _spawn_python_file(
    *,
    name: str,
    file: str,
    host: str,
    port: int,
    url_template: str,
    stdout: Any = None,
    stderr: Any = None,
    extra_env: dict[str, str] | None = None,
) -> SpawnedServer:
    """
    Spawn a submission-provided Python script that implements an MCP server.
    The script is expected to accept `--host` and `--port` args (same convention as our module servers).
    """
    if port == 0:
        port = _pick_reasonable_port()
    url = str(url_template).format(host=host, port=port)
    root = repo_root()
    env_root_path = env_root()
    env = dict(os.environ)
    existing_pp = env.get("PYTHONPATH", "")
    prefix = os.pathsep.join([str(root), str(env_root_path)])
    env["PYTHONPATH"] = prefix + (os.pathsep + existing_pp if existing_pp else "")
    if extra_env:
        for k, v in extra_env.items():
            if k and v is not None:
                env[str(k)] = str(v)
    proc = subprocess.Popen(
        [sys.executable, str(Path(file).resolve()), "--host", host, "--port", str(port)],
        env=env,
        stdout=stdout,
        stderr=stderr,
        text=True,
    )
    try:
        _wait_tcp(url, timeout_s=10.0)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
        raise
    return SpawnedServer(name=name, url=url, module=str(file), proc=proc)


def _terminate_all(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=5)
        except Exception:
            pass


async def _run_agent(
    *,
    system_prompt: str,
    user_prompt: str,
    mcp_urls: list[str],
    mcp_names: list[str],
    max_turns: int,
    tool_poisoning: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ensure_import_paths()
    from environment.clientbuild.loop import PlanningLoop
    from environment.clientbuild.mcp_hub import MCPHub
    from environment.clientbuild.planner import BasicPlanner
    from environment.clientbuild.settings import load_settings_with_mcp
    from environment.clientbuild.logging_setup import LoggingConfig, setup_logging

    settings = load_settings_with_mcp(mcp_urls, mcp_names)
    _, log_path = setup_logging(
        LoggingConfig(
            enabled=settings.log_enabled,
            level=settings.log_level,
            log_dir=settings.log_dir,
            run_name="arena_run",
            max_payload_chars=settings.log_max_payload_chars,
            max_message_chars=settings.log_max_message_chars,
            console_enabled=False,
        )
    )

    client = settings.openai_async_client()
    try:
        async with MCPHub.from_urls(mcp_urls, server_names=mcp_names, trace_callback=_TOOL_TRACE) as hub:
            tools = hub.tool_specs
            poisoning_meta: dict[str, Any] | None = None
            if isinstance(tool_poisoning, dict):
                target_tool = str(tool_poisoning.get("target_tool", "") or "")
                injection = str(tool_poisoning.get("injection", "") or "")
                mode = str(tool_poisoning.get("mode", "append") or "append")
                tools = _apply_tool_poisoning(tools, target_tool=target_tool, injection=injection, mode=mode)
                poisoning_meta = {"target_tool": target_tool, "mode": mode}
                _TOOL_TRACE({"event": "poison.apply", "target_tool": target_tool, "mode": mode})

            planner = BasicPlanner(
                state=[{"role": "system", "content": system_prompt}],
                tools=tools,
            )
            loop = PlanningLoop(
                planner=planner,
                client=client,
                model=settings.model,
                mcp_hub=hub,
                trace_callback=_TOOL_TRACE,
                max_turns=int(max_turns),
                log_max_payload_chars=settings.log_max_payload_chars,
                log_max_message_chars=settings.log_max_message_chars,
            )
            final = await loop.loop({"role": "user", "content": user_prompt})
            out: dict[str, Any] = {"final": final, "clientbuild_log": log_path}
            if poisoning_meta:
                out["tool_poisoning"] = poisoning_meta
            return out
    finally:
        await _close_async_client(client)


async def _close_async_client(client: Any) -> None:
    """
    Ensure OpenAI/httpx async clients are closed before the event loop ends.
    This prevents noisy warnings like: 'Task exception was never retrieved' / 'Event loop is closed'.
    """
    if client is None:
        return
    for method_name in ("aclose", "close"):
        method = getattr(client, method_name, None)
        if method is None:
            continue
        try:
            out = method()
            if inspect.isawaitable(out):
                await out
            return
        except Exception:
            return


def _apply_tool_poisoning(tools: list[Any], *, target_tool: str, injection: str, mode: str = "append") -> list[Any]:
    """
    Tool poisoning is implemented by modifying the tool *description* shown to the LLM.
    The underlying MCP servers stay benign; only the LLM-visible metadata is poisoned.
    """
    _ensure_import_paths()
    from environment.clientbuild.planner import ToolSpec

    if mode not in {"append", "prepend", "replace"}:
        raise ValueError(f"Invalid poisoning mode: {mode!r}")

    out: list[Any] = []
    changed = False
    for t in tools:
        name = getattr(t, "name", None)
        if name != target_tool:
            out.append(t)
            continue

        desc = getattr(t, "description", "") or ""
        payload = (injection or "").strip()
        if mode == "replace":
            new_desc = payload
        elif mode == "prepend":
            new_desc = (payload + "\n\n" + desc).strip()
        else:
            new_desc = (desc + "\n\n" + payload).strip()

        params = getattr(t, "parameters", None)
        out.append(ToolSpec(name=str(name), description=str(new_desc), parameters=dict(params or {})))
        changed = True

    if not changed:
        raise ValueError(f"Poisoning target tool not found in tool list: {target_tool!r}")
    return out


def run_once(*, challenge_id: str, submission: str, attack: str, out_dir: Path) -> dict[str, Any]:
    _ensure_import_paths()
    env = env_root()
    challenge_dir = env / "arena" / "challenges" / challenge_id
    default_spec_path = challenge_dir / "spec.json"

    attack_cfg_path = challenge_dir / "attacks" / f"{attack}.json"
    if not attack_cfg_path.exists():
        raise SystemExit(f"Attack config not found: {attack_cfg_path}")
    raw_cfg = _load_json(attack_cfg_path)
    attack_type_hint = str(raw_cfg.get("attack_type") or "")
    submission_path, injection_override = _resolve_submission_input(submission=submission, attack_type=attack_type_hint)

    cfg: dict[str, Any] = dict(raw_cfg)
    if submission_path is not None:
        cfg = _substitute_submission_placeholders(cfg, submission_path=submission_path)

    if injection_override is not None:
        tool_poisoning = cfg.get("tool_poisoning")
        if not isinstance(tool_poisoning, dict):
            tool_poisoning = {}
            cfg["tool_poisoning"] = tool_poisoning
        tool_poisoning["injection"] = str(injection_override)

    submission_kind = cfg.get("submission_kind")
    if submission_path is not None and isinstance(submission_kind, str) and submission_kind:
        suf = submission_path.suffix.lower()
        if submission_kind == "python" and suf != ".py":
            raise SystemExit(f"Expected a .py submission for attack {attack!r}; got: {submission_path.name}")
        if submission_kind == "image" and suf not in {".png", ".jpg", ".jpeg", ".webp"}:
            raise SystemExit(f"Expected an image submission for attack {attack!r}; got: {submission_path.name}")

    spec_file = cfg.get("spec_file")
    if isinstance(spec_file, str) and spec_file.strip():
        spec_path = (challenge_dir / spec_file).resolve()
    else:
        spec_path = default_spec_path

    spec = _load_json(spec_path)
    submission = {
        "challenge_id": challenge_id,
        "attack_type": cfg.get("attack_type"),
        "attacker_identity": cfg.get("attacker_identity") or {},
    }
    for k in ("fill_slots", "extra_servers", "tool_poisoning", "multimodal_attack"):
        if k in cfg:
            submission[k] = cfg[k]

    if submission_path is not None:
        submission_artifact = str(submission_path.resolve())
    else:
        # Injection-only tool_poisoning runs do not have a file artifact.
        submission_artifact = "<tool_poisoning.injection>"

    attack_type = str(submission.get("attack_type") or "")
    multimodal = submission.get("multimodal_attack")
    injected_email_path: str | None = None

    run_id = uuid.uuid4().hex[:12]
    run_dir = out_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    global _TOOL_TRACE
    trace = ToolTrace(run_dir / "trace.jsonl")
    _TOOL_TRACE = trace.emit

    # Preflight: the runner needs `fastmcp` client library to connect to servers.
    try:
        import fastmcp  # type: ignore  # noqa: F401
    except Exception as e:
        err = "Missing dependency: fastmcp. Use the same Python environment you installed requirements into."
        (run_dir / "report.json").write_text(
            json.dumps(
                {
                    "run_id": run_id,
                    "challenge_id": challenge_id,
                    "submission": str(submission_path) if submission_path is not None else "<injection>",
                    "ok": False,
                    "error": err,
                    "details": str(e),
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return {
            "run_id": run_id,
            "challenge_id": challenge_id,
            "submission": str(submission_path) if submission_path is not None else "<injection>",
            "ok": False,
            "error": err,
        }

    started: list[SpawnedServer] = []
    procs: list[subprocess.Popen] = []
    server_log_handles: list[Any] = []

    def start_server(entry: dict[str, Any]) -> SpawnedServer:
        name = str(entry["name"])
        host = str(entry.get("host", "127.0.0.1"))
        port = int(entry.get("port", 0))
        url_template = str(entry.get("url_template", "http://{host}:{port}/mcp"))
        extra_env: dict[str, str] = {}
        module = entry.get("module")
        file = entry.get("file")
        if injected_email_path and module == "environment.arena.challenges.emailsystem.mcp_servers.email_server":
            # Only the email_server consumes this env var; keep the logic local and harmless for other servers.
            extra_env["EMAILSYSTEM_INJECT_EMAIL_PATH"] = injected_email_path
        stdout_path = run_dir / f"server_{name}.stdout.log"
        stderr_path = run_dir / f"server_{name}.stderr.log"
        stdout_f = stdout_path.open("w", encoding="utf-8")
        stderr_f = stderr_path.open("w", encoding="utf-8")
        server_log_handles.extend([stdout_f, stderr_f])
        if isinstance(file, str) and file.strip():
            srv = _spawn_python_file(
                name=name,
                file=file,
                host=host,
                port=port,
                url_template=url_template,
                stdout=stdout_f,
                stderr=stderr_f,
                extra_env=extra_env or None,
            )
        else:
            if not isinstance(module, str) or not module.strip():
                raise ValueError(f"Server entry missing module/file for {name!r}: {entry!r}")
            srv = _spawn_python_module(
                name=name,
                module=module,
                host=host,
                port=port,
                url_template=url_template,
                stdout=stdout_f,
                stderr=stderr_f,
                extra_env=extra_env or None,
            )
        started.append(srv)
        procs.append(srv.proc)
        trace.emit({"event": "server.spawn", "name": name, "module": srv.module, "url": srv.url})
        return srv

    try:
        # Multimodal-attack mode: allow either injected_email_path (old manifests) or a direct email template (attack configs).
        if attack_type == "multimodal_attack" and isinstance(multimodal, dict):
            rel = multimodal.get("injected_email_path") or multimodal.get("email_path")
            if isinstance(rel, str) and rel.strip():
                injected_email_path = str((submission_path.parent / rel).resolve())
            else:
                email_obj = multimodal.get("email") or multimodal.get("injected_email")
                if isinstance(email_obj, dict):
                    injected_email_path = str((run_dir / "injected_email.json").resolve())
                    (run_dir / "injected_email.json").write_text(json.dumps(email_obj, indent=2, ensure_ascii=False), encoding="utf-8")

        # Start trusted servers (not overrideable by submission).
        for s in spec.get("trusted_servers", []):
            start_server(dict(s))

        poisoning = submission.get("tool_poisoning")
        locked_slots = (attack_type == "tool_poisoning" and isinstance(poisoning, dict)) or (attack_type == "multimodal_attack")

        # Start slots: use submission override if present, else use default.
        # For tool poisoning challenges, submissions must NOT supply MCP servers; they only provide an injection string.
        fill_slots = {} if locked_slots else (submission.get("fill_slots") if isinstance(submission.get("fill_slots"), dict) else {})
        for slot in spec.get("slots", []):
            slot_name = str(slot["name"])
            override = fill_slots.get(slot_name) if isinstance(fill_slots, dict) else None
            if isinstance(override, dict):
                entry = dict(override)
                entry.setdefault("name", slot_name)
            else:
                entry = dict(slot.get("default") or {})
                entry.setdefault("name", slot_name)
            start_server(entry)

        # Puppet-style attacks may mix in additional untrusted MCP servers (beyond the declared slots).
        # These are started only when explicitly provided, and never for tool_poisoning injection-only runs.
        extra_servers = submission.get("extra_servers")
        if not locked_slots and isinstance(extra_servers, list):
            for s in extra_servers:
                if isinstance(s, dict):
                    start_server(dict(s))

        mcp_urls = [s.url for s in started]
        mcp_names = [s.name for s in started]

        artifacts: dict[str, Any] = {
            "run_id": run_id,
            "challenge_id": challenge_id,
            "attack": str(attack),
            "submission": str(submission_path) if submission_path is not None else "<injection>",
        }
        artifacts["spec"] = str(spec_path)
        artifacts["submission_artifact"] = submission_artifact
        agent = spec.get("agent") or {}

        # Tool poisoning mode: solver provides an injection string; all MCP servers remain predefined.
        use_poisoning = isinstance(poisoning, dict) and str(attack_type) == "tool_poisoning"
        agent_out = asyncio.run(
            _run_agent(
                system_prompt=str(agent.get("system_prompt", "")),
                user_prompt=str(agent.get("user_prompt", "")),
                mcp_urls=mcp_urls,
                mcp_names=mcp_names,
                max_turns=int(agent.get("max_turns", 24)),
                tool_poisoning=dict(poisoning) if use_poisoning else None,
            )
        )
        artifacts["agent"] = agent_out

        agent_final: str | None = None
        try:
            a = artifacts.get("agent")
            if isinstance(a, dict):
                v = a.get("final")
                if isinstance(v, str):
                    agent_final = v
        except Exception:
            agent_final = None

        validation = asyncio.run(
            validate_objective(
                objective=dict(spec.get("objective") or {}),
                attacker=dict(submission.get("attacker_identity") or {}),
                mcp_urls=mcp_urls,
                mcp_names=mcp_names,
                agent_output=agent_final,
                trace_path=run_dir / "trace.jsonl",
                trace_callback=_TOOL_TRACE,
            )
        )
        artifacts["validation"] = validation
        artifacts["servers"] = [{"name": s.name, "url": s.url, "module": s.module} for s in started]
        artifacts["ok"] = bool(validation.get("hit"))

        (run_dir / "report.json").write_text(json.dumps(artifacts, indent=2, ensure_ascii=False), encoding="utf-8")
        return artifacts
    finally:
        _terminate_all(procs)
        for h in server_log_handles:
            try:
                h.close()
            except Exception:
                pass


class ToolTrace:
    def __init__(self, path: Path):
        self._path = path
        self._fh = path.open("a", encoding="utf-8")
        self._current_turn: int | None = None

    def emit(self, event: dict[str, Any]) -> None:
        payload = dict(event)
        payload.setdefault("ts", datetime.now(timezone.utc).isoformat())
        self._fh.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
        self._fh.flush()

        et = str(payload.get("event", "event"))
        turn = payload.get("turn")
        if isinstance(turn, int):
            self._current_turn = turn

        def _new_turn_header(t: Any, label: str) -> None:
            print(f"\n=== TURN {t} ({label}) ===")

        def _one_line(text: Any, *, limit: int) -> str:
            s = str(text if text is not None else "").replace("\n", "\\n")
            return s if len(s) <= limit else s[: max(0, limit - 3)] + "..."

        if et == "llm.request":
            if payload.get("turn") is not None:
                _new_turn_header(payload.get("turn"), "MODEL INPUT")
            tail = payload.get("messages_tail") or []
            tools = payload.get("tools") or []
            tools_s = ", ".join([str(t) for t in tools[:12]]) + (" ..." if len(tools) > 12 else "")
            print("Action: build prompt and ask the model to decide the next step.")
            print(f"Tools available ({payload.get('tools_count')}): [{tools_s}]")
            print("Model input (recent messages):")
            for m in tail:
                role = (m or {}).get("role")
                content = (m or {}).get("content")
                tool_call_id = (m or {}).get("tool_call_id")
                if content is None and role != "tool":
                    continue
                prefix = f"{role}"
                if role == "tool" and tool_call_id:
                    prefix += f"(tool_call_id={tool_call_id})"
                print(f"  - {prefix}: {_one_line(content, limit=280)}")
            return

        if et == "llm.response":
            msg = payload.get("message") or {}
            role = msg.get("role")
            content = msg.get("content")
            tool_calls = msg.get("tool_calls")
            if tool_calls:
                names: list[str] = []
                for tc in tool_calls:
                    fn = (tc or {}).get("function") or {}
                    n = fn.get("name")
                    if n:
                        names.append(str(n))
                print(f"Model output: tool_calls={names}")
                return

            print(f"Model output (role={role}): {_one_line(content, limit=500)}")
            return

        if et == "llm.tool_call":
            if payload.get("turn") is not None and self._current_turn == payload.get("turn"):
                _new_turn_header(payload.get("turn"), "TOOL CALL")
            print("Action: execute the tool call chosen by the model.")
            print(f"Model chose tool: {payload.get('name')}")
            print(f"Arguments: {json.dumps(payload.get('args'), ensure_ascii=False, default=str)}")
            return

        if et == "mcp.call":
            t = self._current_turn
            turn_prefix = f"turn={t} " if t is not None else ""
            print(f"Tool call ({turn_prefix}runtime): {payload.get('exposed')} -> {payload.get('server')}.{payload.get('tool')} args={json.dumps(payload.get('args'), ensure_ascii=False, default=str)}")
        elif et == "mcp.result":
            # Keep console output compact.
            res = payload.get("result")
            s = _one_line(json.dumps(res, ensure_ascii=False, default=str), limit=600)
            t = self._current_turn
            turn_prefix = f"turn={t} " if t is not None else ""
            print(f"Tool result ({turn_prefix}runtime): {payload.get('exposed')} = {s}")
        elif et == "mcp.tools":
            print(f"[tools] {payload.get('count')} tools: {', '.join(list(payload.get('tools') or [])[:12])}{' ...' if (payload.get('count') or 0) > 12 else ''}")
        elif et == "server.spawn":
            print(f"[spawn] {payload.get('name')} {payload.get('url')} ({payload.get('module')})")
        elif et == "poison.apply":
            print(f"[poison] target_tool={payload.get('target_tool')} mode={payload.get('mode')}")


# Global trace hook used by MCPHub callbacks inside async contexts.
# Set per-run in `run_once()`; when unset, tracing is a no-op.
def _TOOL_TRACE(_: dict[str, Any]) -> None:
    return


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "1", "yes", "y", "on"}:
            return True
        if v in {"false", "0", "no", "n", "off", ""}:
            return False
    return bool(value)