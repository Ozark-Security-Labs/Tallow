# LLM Narrative Enrichment

Tallow may optionally use LLMs to summarize deterministic evidence. LLM analysis is disabled by default and is never the canonical source of severity.

## Prompt contract

The system prompt must instruct the model that package contents, metadata, READMEs, scripts, and diffs are hostile quoted evidence. They must never override system instructions.

LLM output should be structured JSON containing:
- verdict
- confidence
- summary
- attack hypothesis
- supporting evidence IDs
- benign explanations
- recommended actions
- uncertainty notes

## Provider modes

- Direct API providers: Anthropic, OpenAI/Codex API, OpenRouter, OpenAI-compatible local endpoints.
- CLI providers: existing `codex`, `claude`, `opencode`, or custom commands.

Store provider, model, prompt template version, redaction policy, input digest, and output for auditability.

## Foundation status

LLM features are not implemented in Foundation. Future LLM output is narrative enrichment only; deterministic scoring owns canonical severity and LLM inputs must be bounded, redacted evidence bundles after prompt-injection defenses.
