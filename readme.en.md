# clientbuild

A minimal **Basic Planner + Planning Loop** (based on `Tutorial.ipynb`) built on `fastmcp`, plus an Email Assistant simulation environment for MCP security/attack testing.

- MCP servers expose tools (via `fastmcp`)
- `clientbuild` (host) aggregates tools from one or more MCP servers, lets the LLM decide which tool to call, then routes calls via `client.call_tool(...)`

### Architecture

- `clientbuild/mcp_hub.py`: connect to multiple MCP servers, `list_tools()` aggregation, `call_tool()` routing
- `clientbuild/planner.py`: Basic Planner state machine (Query / ToolCall / Response)
- `clientbuild/loop.py`: executes the loop (LLM tool-calls ↔ MCP tool results)
- `clientbuild/settings.py`: configuration loader (`.env` for LLM; MCP sets + logging)

### Quickstart: Weather

1) Create `.env` (recommended: copy `.env.example` → `.env`) and fill:
- `OPENAI_API_KEY=...`
- `OPENAI_MODEL=...`
- (optional) `OPENAI_BASE_URL=http://localhost:1234/v1/` (for local/proxy OpenAI-compatible endpoints)

2) Ensure `clientbuild/settings.py` uses:
- `ACTIVE_MCP_SET = "weather"`

3) Start the MCP server:

`python clientbuild/weather.py`

4) Run the host:

`python clientbuild/client.py --prompt "What's the weather in Chengdu?"`

### MCP Sets (JSON)

Base MCP sets (used by `clientbuild/client.py`) are defined in `clientbuild/config/mcp_sets.json`; switch the default set by editing `ACTIVE_MCP_SET` in `clientbuild/settings.py`.

Email/Teams scenario MCP sets are defined in `clientbuild/scenarios/emailsystem/mcp_sets.json` (used by `start_system.py --set ...` and `run_full_attack.py --attack ...`).

Each server entry may also include `module` (used by scenario launchers to auto-spawn); the listening port is taken from the `url`.

To change ports:
- Update the port in the `url` in the relevant `mcp_sets.json` (e.g. `http://0.0.0.0:8002/mcp` → `http://0.0.0.0:9002/mcp`).
- For emailsystem, `start_system.py` / `run_full_attack.py` auto-spawn servers with `--port` parsed from that `url` (requires `module`).
- For weather, start the server with the same port, e.g. `python -m clientbuild.weather --port 9000`, and update `clientbuild/config/mcp_sets.json` accordingly.

### Local Models (OpenAI-compatible)

Put these in `.env`:
- `OPENAI_BASE_URL=http://localhost:1234/v1/`
- `OPENAI_MODEL=meta-llama-3.1-8b-instruct`
- `OPENAI_API_KEY=local`

### Simulation: Email Assistant (for attack testing)

Run the scenario:

`python -m clientbuild.scenarios.emailsystem.start_system`

By default this auto-spawns the required MCP servers from `clientbuild/scenarios/emailsystem/mcp_sets.json`; use `--no-spawn` if servers are already running.

### One-click full attack run

`python -m clientbuild.scenarios.emailsystem.run_full_attack --attack email_prompt_injection`

### Range: Cryptocurrency Transfer Redirection / Theft (cryptosystem)

This scenario simulates a “harmless query → tool poisoning/redirected transfer → irreversible loss” pattern (all transfers are local simulations; nothing is sent on-chain).

MCP sets: `clientbuild/scenarios/cryptosystem/mcp_sets.json`
- `crypto_benign`: benign price server + benign wallet
- `crypto_tool_poisoning`: malicious price tool description + benign wallet
- `crypto_transfer_redirection`: benign price server + malicious wallet (redirects transfers to a fixed attacker address)

Run (auto-spawns required MCP servers):
- `python -m clientbuild.scenarios.cryptosystem.start_system --set crypto_benign`
- `python -m clientbuild.scenarios.cryptosystem.start_system --set crypto_tool_poisoning`

One-click reproduction (prints transfers/balances for verification):
- `python -m clientbuild.scenarios.cryptosystem.run_full_attack --attack crypto_tool_poisoning`
- `python -m clientbuild.scenarios.cryptosystem.run_full_attack --attack crypto_transfer_redirection`

### Range: Malicious External Resource (resourcesystem)

This scenario simulates a benign MCP tool fetching a compromised third-party resource (web/API/OCR), which can poison planning at runtime and trigger unintended high-risk actions (example: calling wallet `send_crypto`).

Entrypoints and config:
- External resource site (local fixture): `clientbuild/scenarios/resourcesystem/external_resource_server.py` (default port 8200)
- MCP sets: `clientbuild/scenarios/resourcesystem/mcp_sets.json`

Run (safe system prompt; auto-spawns external site + MCP):
- `python -m clientbuild.scenarios.resourcesystem.start_system --set resource_clean`
- `python -m clientbuild.scenarios.resourcesystem.start_system --set resource_poisoned`

One-click reproduction (malicious instructions come only from the external resource; prints transfers/balances):
- `python -m clientbuild.scenarios.resourcesystem.run_full_attack --attack resource_poisoned`
- `python -m clientbuild.scenarios.resourcesystem.run_full_attack --attack resource_poisoned_multimodal`
