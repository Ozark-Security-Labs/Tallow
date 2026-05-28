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
```

- `secure_cookies` should stay `true` outside local development.
- `dev_insecure_cookies` is only for local HTTP testing.
- The bootstrap admin password must come from an environment or secret reference, not from committed YAML.
- Once a persisted admin exists, bootstrap admin login is disabled.
