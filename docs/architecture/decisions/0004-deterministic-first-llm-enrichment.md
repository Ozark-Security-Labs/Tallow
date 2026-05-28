# ADR 0004: Deterministic-first LLM enrichment

## Status

Accepted for Milestone 6.

## Context

Tallow's security decisions come from deterministic analyzers, registry/SCM evidence, hash verification, policy, and reviewer actions. Operators may still want optional narrative summaries to speed review.

## Decision

LLM enrichment is disabled by default and explicit when enabled. Providers receive only prepared, bounded, redacted request objects. LLM output is stored separately from findings and labeled as narrative enrichment. It cannot create findings, delete findings, change canonical severity, change policy, grant tools, or trigger commands.

Provider metadata (`provider_type`, `provider_name`, `model`, `prompt_template_version`, and `input_digest`) is retained for auditability.

## Consequences

- Deterministic scoring remains authoritative.
- UI/API must distinguish LLM narrative from deterministic evidence.
- Prompt template, redaction, and output validation issues build on this boundary.
