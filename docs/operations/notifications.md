# Notifications

Initial notification integrations are email and Microsoft Teams. Future routes include Slack, Discord, generic webhooks, GitHub/GitLab issues, Jira, Linear, PagerDuty, Opsgenie, RSS/Atom, and SIEM/syslog.

## Template schema

Notification templates are deterministic, evidence-bound documents validated against `schemas/notification-template.schema.json` and the Go validator in `internal/notifications/templates`.

Each template declares:

- `id`, `version`, and `description`;
- `compatible_channels` (`email`, `teams`);
- every variable with type, required flag, description, and redaction policy;
- channel targets such as `email.subject`, `email.text`, `email.html`, and `teams.card_json`.

Validation fails when a target references an undeclared variable, a compatible channel is missing its required body, or a template declares raw artifact content, webhook URL, token, or secret variables. Templates may link to evidence summaries or triage URLs, but must not include raw artifact contents.

Run:

```sh
python scripts/validate_notification_templates.py internal/notifications/templates
```
