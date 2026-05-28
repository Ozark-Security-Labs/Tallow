# Deployment Configuration

Deployment config uses YAML for non-secret settings and `_env` references for secrets.

## Auth and sessions

```yaml
auth:
  session:
    cookie_name: tallow_session
    ttl: 24h
    secure_cookies: true
    dev_insecure_cookies: false
  local:
    enabled: true
    bootstrap_admin_email: admin@example.com
    bootstrap_admin_password_env: TALLOW_BOOTSTRAP_ADMIN_PASSWORD
  github:
    enabled: false
    client_id: ""
    client_secret_env: TALLOW_GITHUB_CLIENT_SECRET
    callback_url: http://localhost:8844/v1/auth/github/callback
    allowed_orgs: []
    allowed_teams: []
```

- `secure_cookies` should stay `true` outside local development.
- `dev_insecure_cookies` is only for local HTTP testing.
- The bootstrap admin password must come from an environment or secret reference, not from committed YAML.
- Once a persisted admin exists, bootstrap admin login is disabled.
- GitHub `allowed_orgs` and `allowed_teams` are optional allow hooks. When both are empty, any successfully authenticated GitHub identity is accepted for identity mapping and then receives Tallow-owned roles.


## Optional LLM narrative enrichment

LLM narrative enrichment is disabled by default and is non-authoritative. Deterministic findings, severity, policy, and alerts continue to work without an LLM provider.

```yaml
llm:
  enabled: false
  provider:
    type: "" # fake, cli, api, or openai_compatible when explicitly enabled
    name: ""
    model: ""
    command: []
    endpoint: ""
    api_key_env: TALLOW_LLM_API_KEY
  prompt_template: configs/llm/prompts/narrative-v1.yaml
  redaction_policy: configs/redaction/default.yaml
  max_evidence_items: 20
  max_snippet_bytes: 4096
  timeout_seconds: 30
  store_prompts: false
  store_outputs: true
```

Environment equivalents include `TALLOW_LLM_ENABLED`, `TALLOW_LLM_PROVIDER_TYPE`, `TALLOW_LLM_PROVIDER_NAME`, `TALLOW_LLM_PROVIDER_MODEL`, `TALLOW_LLM_PROVIDER_COMMAND`, `TALLOW_LLM_PROVIDER_ENDPOINT`, and `TALLOW_LLM_PROVIDER_API_KEY_ENV`. API keys must come from environment or secret references, not committed YAML.
