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

## Email templates

The initial email templates are:

- `email.high_risk_finding`: package/version/ecosystem, severity, confidence, rule IDs, concise evidence summary, redacted triage URL, and reviewer action.
- `email.scan_failed`: package/version/ecosystem, analyzer run ID, sanitized error, and redacted triage URL.
- `email.digest`: digest window, finding totals, critical/high counts, package summary, and redacted triage URL.

Every email template has plaintext and HTML targets. Snapshot tests cover both variants and use wording such as “signals requiring review,” not unsupported claims of confirmed malware.

## Microsoft Teams templates

The initial Teams templates are:

- `teams.high_risk_finding`: Adaptive Card JSON with package, version, severity, rule IDs, and redacted evidence link.
- `teams.scan_failed`: compact message JSON with package, version, severity, rule context, and redacted evidence link.
- `teams.digest`: compact digest message JSON with package summary, window, highest severity, rules, and redacted evidence link.

Teams template tests parse and compare canonical JSON snapshots. Templates must not render webhook URLs, OAuth tokens, raw artifact bodies, or untrusted markdown action spoofing content.

## Routes and delivery audit

Notification routes select a channel and sanitized configuration. Email routes use SMTP host, port, sender, recipients, and a password secret reference. Teams routes use a webhook/workflow URL secret reference. Delivery dispatch records pending/sent/failed attempts with route, alert/finding, channel, attempt count, provider message ID, timestamps, and sanitized errors. Raw artifact bodies, webhook URLs, SMTP passwords, OAuth tokens, and full sensitive URLs must not be stored in delivery errors or rendered previews.

Admin-only APIs manage routes and send test notifications. Analysts and admins may read/triage alerts; notification route management and integration tests are admin-only.

Run:

```sh
python scripts/validate_notification_templates.py internal/notifications/templates
```
