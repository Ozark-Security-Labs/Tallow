# LLM Narrative Enrichment

Tallow may optionally use LLMs to summarize deterministic evidence. LLM analysis is disabled by default in Go configuration, Docker Compose, and Helm planning. It is never the canonical source of severity, confidence, policy decisions, finding creation, hash status, or alert routing.

## Provider abstraction

Milestone 6 defines provider modes without enabling any provider by default:

- `fake`: deterministic local test provider used by unit and regression tests.
- `cli`: argv-based local command provider. Tallow sends a prepared request on stdin and reads JSON from stdout; it does not pass package text to a shell.
- `api`: generic HTTPS JSON API provider using Tallow's provider request contract.
- `openai_compatible`: OpenAI-compatible HTTPS mode reserved for compatible endpoints; it uses the same prepared request boundary in this milestone.

Enabled providers must declare provider type, provider name, model, prompt template version, timeout, and an input digest. API providers must use an environment-variable secret reference rather than a committed key.

## Disabled default

The zero/default configuration has `llm.enabled=false`. When disabled, narrative generation returns a typed disabled error and does not call a provider.

Example disabled configuration:

```yaml
llm:
  enabled: false
```

Example environment for a test-only fake provider:

```sh
TALLOW_LLM_ENABLED=true
TALLOW_LLM_PROVIDER_TYPE=fake
TALLOW_LLM_PROVIDER_NAME=fake
TALLOW_LLM_PROVIDER_MODEL=test-narrative
```

## Evidence boundary

Package contents, registry metadata, READMEs, scripts, diffs, maintainer text, issues, and community comments are hostile quoted evidence. Providers receive prepared request objects only. They do not receive filesystem, registry, SCM, database, credential, or analyzer-execution access.

## Narrative separation

LLM text is stored and exposed as `source: llm` narrative enrichment, separate from deterministic findings. API/UI surfaces must label it as optional LLM narrative so reviewers do not confuse it with deterministic analyzer output.

Audit metadata recorded with a narrative includes provider type, provider name, model, prompt template version, input digest, and creation time. Future persistence stores this in narrative/audit tables, not in the findings table.
