# Threat Model

Tallow ingests hostile package metadata and artifacts. Its own pipeline must be treated as a high-risk parser system.

## Assets

- Source/dependency inventory.
- Registry observations and artifact hashes.
- Suspicious artifacts and extracted files.
- Analyzer findings and alerts.
- SCM/API/OAuth credentials.
- Notification webhooks and email credentials.
- Local user/session data.

## Trust boundaries

- Internet package registries to observers.
- Artifact storage to analyzers.
- Analyzer workers to control plane.
- Control plane to PostgreSQL/NATS.
- Notification routes to external systems.
- LLM providers/CLI tools to narrative layer.

## Key threats

- Archive traversal, symlink escape, device files, hardlinks, bombs, oversized artifacts.
- Malicious package contents attempting prompt injection against LLM analysis.
- Registry hash mismatch or same-version artifact mutation.
- Credential leakage through analyzer environments, logs, notifications, or LLM prompts.
- Poisoned community rules or future signal feeds.
- Compromised SCM OAuth token or overly broad provider permissions.

## Default mitigations

- No package code execution by default.
- Analyzer containers run without secrets and should not need outbound network.
- Safe unpacking enforces file count, size, type, and path limits.
- Registry-provided hashes are verified locally.
- Package content is quoted hostile evidence for LLMs.
- Notifications summarize evidence and avoid raw secret-like payloads.
