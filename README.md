# ScamFighter

Open-source defensive email abuse response platform.

Built as the first production application on top of SGRS. Agents reason with PydanticAI; SGRS governs state transitions; MCP servers isolate external capabilities.

## Status

Pre-implementation. See [PRD](./PRD.md) and [implementation plan](./docs/IMPLEMENTATION_PLAN.md).

## Stack

- Python 3.13+
- PydanticAI v2
- SGRS client (public repo)
- FastAPI
- MCP (stdio, local-first)
- uv
- SQLite + local filesystem evidence vault

## Repository layout

```
apps/           # runnable application(s)
packages/       # shared libraries
mcp_servers/    # mail-read, mail-actions, evidence, reporting, threat-intel
policies/       # SGRS / governance policies
schemas/        # strict YAML + Pydantic schemas
docs/           # architecture and plans
tests/          # unit, integration, e2e
```

## Local mode

Everything runs locally by default: SQLite, filesystem evidence, stdio MCP servers, observe-only actions. Optional Ollama Cloud escalation via `OLLAMA_API_KEY`.

```bash
cp .env.example .env
# uv sync   # once dependencies are added
```

## Security posture

Observe-only by default. No hack-back. Immutable evidence. Typed models everywhere. See the PRD security section for the full CI/supply-chain checklist.

## License

MIT
