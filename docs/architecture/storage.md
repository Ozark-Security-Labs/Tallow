# Storage schema

PostgreSQL is the source of truth. Foundation tables cover packages, package versions, artifacts, artifact observations, findings, evidence refs, users, event outbox/inbox, and scheduled jobs. Natural keys prevent package/version/artifact duplication; event inbox/outbox IDs support idempotency.
