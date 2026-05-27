# Rule Authoring

Rules must be deterministic, evidence-bound, and safe on hostile package contents.

## Rule metadata

Each rule declares:
- `rule_id` namespaced and stable.
- `version` semver.
- `description`.
- `category`.
- `default_severity_hint`.
- `default_confidence`.
- `inputs`: `snapshot`, `snapshot_diff`, `hash_verification`, or combinations.
- `limits`: max file bytes, path globs, text/binary policy.

Rule IDs use a lowercase dot-separated namespace with at least two segments:

```text
<ecosystem-or-domain>.<category>.<signal_name>
```

Examples: `network.webhook_url`, `npm.lifecycle.install_script`,
`js.secrets.env_token_access`, `artifact.binary.unexpected`. Use lowercase
letters, digits, and underscores inside segments. Never rename or repurpose an
existing `rule_id`; create a new ID and retire the old one if semantics change.

## Implementation rules

- Do not execute package code.
- Do not import modules from unpacked artifacts.
- Do not follow symlinks into the host filesystem.
- Do not use network access.
- Sort all matches before emitting findings.
- Emit one finding per coherent issue; avoid flooding on repeated tokens in one file.
- Include evidence coordinates whenever possible.

## Good rule pattern

1. Filter candidate files by normalized path and size.
2. Parse or scan with bounded memory.
3. Normalize matches.
4. De-duplicate matches.
5. Emit stable findings with snippets redacted.
6. Add fixture tests for positive, negative, and boundary cases.

## Redaction

Redact secrets in snippets by default. If a rule detects a credential, store enough context to prove the finding without storing the full secret. Hash secret values if correlation is needed.

## Versioning

Change `rule_version` when detection logic, emitted evidence, severity hint, or confidence changes. Do not reuse a rule ID for a different concept.

## Required tests per rule

- Positive fixture triggers expected finding ID shape.
- Negative fixture produces no finding.
- Determinism test runs twice and compares canonical JSON.
- Oversized file/path edge case does not crash.
- Prompt-injection text in file does not affect analyzer behavior.
