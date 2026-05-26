# Tallow Analyzers

Deterministic Python analyzers for unpacked package snapshots and diffs.

## Commands

```bash
uv run --project analyzers pytest
uv run --project analyzers ruff check
uv run --project analyzers tallow-analyzer --list-rules
```

## Safety

Analyzers read snapshot files only. They do not execute package code, import artifact modules, or perform outbound network access.
