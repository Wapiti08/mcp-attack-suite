# Environment

This folder is the **single entrypoint** for running MCP security ranges with a clear separation between:

- **Trusted arena** (challenge author owned): specs, runner, ground-truth state for validation
- **Untrusted submissions** (solver owned): malicious MCP servers / content sources used to attack the agent

## Layout (recommended mental model)

- `environment/arena/` (trusted): challenge specs + runner + validators
- `environment/submissions/` (untrusted): solver submissions (examples included)
- `environment/clientbuild/` (runtime): MCP hub + planner/loop + scenario servers used by the arena
- `environment/docs/` (docs): architecture + usage docs
- `environment/runs/` (generated): run artifacts (`report.json`, logs) — gitignored
- `environment/attackmethodsCollection/` (legacy): notebooks/artifacts kept for reference

## Setup

- Copy `environment/.env.example` → `environment/.env` and fill `OPENAI_API_KEY`, `OPENAI_MODEL` (optional: `OPENAI_BASE_URL`).
- If you don't want to install extra deps, `environment/clientbuild/settings.py` can parse `environment/.env` without `python-dotenv` (but installing `python-dotenv` is recommended).

## Run arena (recommended)

- Dry run (no LLM):\
  `python -m environment.arena.runner run --challenge cryptosystem --attack tool_poisoning --submission environment/tests/genImage/blank_with_text.png --no-agent`
- With agent (needs working `.env`):\
  `python -m environment.arena.runner run --challenge emailsystem --attack puppet --submission environment/submissions/examples/emailsystem/puppet/puppet_inbox_server.py`

See `environment/docs/ARENA_ARCHITECTURE.md`.

Tool poisoning note: for `attack_type="tool_poisoning"`, submissions provide only `tool_poisoning.injection`; they do not provide custom MCP servers.

### Multimodal email arena (optional)

- Multimodal summary arena (inserts an image email via submission data):\
  `python -m environment.arena.runner run --challenge emailsystem --attack multimodal_attack --submission environment/submissions/examples/emailsystem/multimodal_attack/assets/safe.png`

## LLM connection test (optional)

- Opt-in integration test for `.env` LLM config:\
  `RUN_LLM_CONNECTION_TEST=1 python -m unittest environment/tests/connection/test_llm_env_connection.py`

## Run clientbuild demos (optional)

`clientbuild` is the minimal host implementation (planner/loop + MCP hub). Typical commands:

- Weather demo (manual server + host):
  - `python -m environment.clientbuild.weather --port 8000`
  - `python -m environment.clientbuild.client --mcp http://127.0.0.1:8000/mcp --prompt "What's the weather in Chengdu?"`

Scenario implementations live under `environment/arena/challenges/*/`. They are “trusted arena” code.
