from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import json
import warnings


@dataclass(frozen=True)
class Settings:
    model: str
    base_url: str | None
    api_key: str | None
    mcp_urls: list[str]
    mcp_names: list[str] | None
    log_enabled: bool
    log_level: str
    log_dir: str
    log_max_payload_chars: int
    log_max_message_chars: int

    def openai_async_client(self):
        from openai import AsyncOpenAI

        kwargs: dict[str, str] = {}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        if self.api_key:
            kwargs["api_key"] = self.api_key
        return AsyncOpenAI(**kwargs)


# =========================
# Edit this config section
# =========================

# Which MCP set to use by default.
# - "weather": matches the original single-server demo (`clientbuild/weather.py`, port 8000)
ACTIVE_MCP_SET: str = "weather"

_CLIENTBUILD_DIR = Path(__file__).resolve().parent

MCP_SETS_PATH = _CLIENTBUILD_DIR / "config" / "mcp_sets.json"


def load_mcp_sets(path: Path = MCP_SETS_PATH) -> dict[str, list[dict[str, str]]]:
    if not path.exists():
        raise RuntimeError(f"Missing MCP sets config: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"Invalid MCP sets config (expected object): {path}")

    out: dict[str, list[dict[str, str]]] = {}
    for set_name, servers in raw.items():
        if not isinstance(set_name, str) or not isinstance(servers, list):
            raise RuntimeError(f"Invalid MCP sets entry: {set_name!r}")
        normalized: list[dict[str, str]] = []
        for s in servers:
            if not isinstance(s, dict):
                raise RuntimeError(f"Invalid server entry in {set_name!r}: {s!r}")
            name = s.get("name")
            url = s.get("url")
            module = s.get("module")
            if not isinstance(name, str) or not isinstance(url, str):
                raise RuntimeError(f"Server entry must have string name/url in {set_name!r}: {s!r}")
            if module is not None and not isinstance(module, str):
                raise RuntimeError(f"Server entry module must be string when present in {set_name!r}: {s!r}")
            entry: dict[str, str] = {"name": name, "url": url}
            if module:
                entry["module"] = module
            normalized.append(entry)
        out[set_name] = normalized
    return out


MCP_SETS: dict[str, list[dict[str, str]]] = load_mcp_sets()

LOGGING = {
    "enabled": True,
    "level": "DEBUG",  # DEBUG/INFO/WARNING/ERROR
    "dir": "environment/clientbuild/logs",
    "max_payload_chars": 20000,
    "max_message_chars": 4000,
}

# Default model to use when OPENAI_MODEL is not set.
# Kept intentionally simple so this repo can run "out of the box" with minimal config.
DEFAULT_OPENAI_MODEL: str = "gpt-4o-mini"


def load_settings() -> Settings:
    settings = load_settings_with_mcp_set()
    return settings


def load_settings_with_mcp(mcp_urls: list[str], mcp_names: list[str] | None) -> Settings:
    def _load_dotenv_fallback(path: Path, *, override: bool) -> None:
        if not path.exists():
            return
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if not key:
                continue
            if override or (key not in os.environ):
                os.environ[key] = value

    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception:  # pragma: no cover
        load_dotenv = None

    # `clientbuild` lives under `environment/clientbuild/`.
    # Support `environment/.env` and legacy locations under `environment/attackmethodsCollection/`.
    env_root = Path(__file__).resolve().parents[1]
    candidates = [
        env_root / ".env",
        env_root / "clientbuild" / ".env",
        env_root / "attackmethodsCollection" / ".env",
        env_root / "attackmethodsCollection" / "clientbuild" / ".env",
    ]
    for p in candidates:
        if load_dotenv is not None:
            load_dotenv(dotenv_path=p, override=False)
        else:
            _load_dotenv_fallback(p, override=False)

    model = os.getenv("OPENAI_MODEL") or os.getenv("MODEL")
    api_key = os.getenv("OPENAI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL")

    if not model:
        model = DEFAULT_OPENAI_MODEL
        warnings.warn(
            f"OPENAI_MODEL not set; defaulting to {DEFAULT_OPENAI_MODEL!r}. "
            "Set OPENAI_MODEL in `environment/.env` (or `environment/clientbuild/.env`) to override.",
            stacklevel=2,
        )
    if not api_key:
        raise RuntimeError("Missing OPENAI_API_KEY. Put it in `.env` and re-run (local can use a placeholder).")

    return Settings(
        model=str(model),
        base_url=str(base_url) if base_url else None,
        api_key=str(api_key),
        mcp_urls=mcp_urls,
        mcp_names=mcp_names,
        log_enabled=bool(LOGGING.get("enabled", True)),
        log_level=str(LOGGING.get("level", "DEBUG")),
        log_dir=str(LOGGING.get("dir", "environment/clientbuild/logs")),
        log_max_payload_chars=int(LOGGING.get("max_payload_chars", 20000)),
        log_max_message_chars=int(LOGGING.get("max_message_chars", 4000)),
    )


def load_settings_with_mcp_set(mcp_set: str | None = None) -> Settings:
    chosen_set = mcp_set or ACTIVE_MCP_SET
    mcp_servers = MCP_SETS.get(chosen_set)
    if not mcp_servers:
        raise RuntimeError(
            f"Unknown MCP set={chosen_set!r}. Available: {sorted(MCP_SETS.keys())}. "
            f"Edit {MCP_SETS_PATH}."
        )
    mcp_urls = [s["url"] for s in mcp_servers]
    mcp_names = [s["name"] for s in mcp_servers]
    return load_settings_with_mcp(mcp_urls, mcp_names)
