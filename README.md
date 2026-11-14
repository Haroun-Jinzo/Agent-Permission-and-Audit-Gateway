# agent-gateway

A permission and audit gateway that sits between AI agents and their tools.
It limits what a manipulated agent can do and records every decision.
It does **not** prevent prompt injection. See `docs/threat-model.md` for what it
does and does not protect against.

## Development setup (WSL2 + Docker Desktop)

```bash
# keep the repository inside the WSL file system, for example ~/projects/agent-gateway
uv sync                 # create .venv and install everything, including dev tools
uv run pytest           # run the tests
```

## Checks (the same ones CI runs)

```bash
uv run ruff check .             # lint
uv run ruff format --check .    # formatting
uv run mypy                     # type check
uv run pytest                   # tests
```
