# Polling Scheduler

The scheduler discovers registry changes for watched packages. It must be horizontally safe, jittered, and idempotent.

## Watch record fields

- `id`.
- `ecosystem`, `registry_url`, `canonical_name`.
- `enabled`.
- `interval_seconds`.
- `priority`: `low`, `normal`, `high`.
- `next_poll_at`.
- `last_poll_started_at`, `last_poll_finished_at`.
- `last_success_at`, `last_error_at`.
- `consecutive_errors`.
- `lease_owner`, `lease_expires_at`.
- `etag`, `last_modified`, `adapter_cursor`.

## Lease algorithm

1. Select due enabled watches where lease is absent or expired.
2. Acquire with `UPDATE ... WHERE id=? AND (lease_expires_at IS NULL OR lease_expires_at < now())`.
3. Use a unique scheduler instance ID as `lease_owner`.
4. Commit before calling remote registry.
5. Release lease and compute next poll after persistence.

## Backoff and jitter

- Success: `next_poll_at = now + interval_seconds ± 10% jitter`.
- 404/package missing: back off at least 6 hours unless user requested high priority.
- Rate limit: honor `Retry-After`; otherwise exponential backoff capped at 24 hours.
- Network/server errors: exponential backoff with jitter.
- Authentication/config errors: disable watch only when policy says so; otherwise surface operations alert.

## Event publishing

Publish events only after database transaction commits. Use outbox pattern where possible:
- Transaction stores observations and outbox rows.
- Publisher drains outbox to NATS JetStream.
- Mark outbox row published after ack.

Event subjects:
- `package.version.observed.v1`
- `artifact.discovered.v1`
- `artifact.mutated.v1`

## Idempotency

Adapter output must be upserted by natural keys. Re-polling the same package must update `last_observed_at` and not duplicate versions/artifacts/events except explicit observation history rows.

## Metrics

Expose counts and latencies for polls due, leases acquired, adapter errors, rate limits, versions discovered, artifacts discovered, and outbox publish failures.
