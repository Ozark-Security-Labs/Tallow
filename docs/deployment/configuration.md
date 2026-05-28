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
