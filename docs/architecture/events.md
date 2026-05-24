# Event Model

Tallow uses NATS JetStream as the durable workflow spine. Events use versioned JSON envelopes.

## Envelope

```json
{
  "id": "evt_01...",
  "type": "artifact.observed",
  "version": "v1",
  "occurred_at": "2026-05-24T00:00:00Z",
  "producer": "tallow.registry.npm",
  "trace_id": "trc_01...",
  "data": {}
}
```

## Initial subjects

- `tallow.repo.discovered`
- `tallow.repo.synced`
- `tallow.manifest.discovered`
- `tallow.dependency.resolved`
- `tallow.package.watch.created`
- `tallow.package.poll.requested`
- `tallow.package.poll.completed`
- `tallow.version.discovered`
- `tallow.version.changed`
- `tallow.artifact.download.requested`
- `tallow.artifact.downloaded`
- `tallow.artifact.hash.verified`
- `tallow.artifact.hash.mismatch`
- `tallow.artifact.changed`
- `tallow.analysis.requested`
- `tallow.analysis.completed`
- `tallow.analysis.failed`
- `tallow.finding.created`
- `tallow.impact.calculated`
- `tallow.alert.created`
- `tallow.notification.queued`
- `tallow.notification.sent`
- `tallow.notification.failed`
- `tallow.llm.review.requested`
- `tallow.llm.review.completed`

## Delivery assumptions

JetStream is at-least-once. Consumers must be idempotent where practical. Event payloads should reference database IDs/artifact IDs rather than embedding large package content.

## Request IDs

HTTP and event flows use `X-Request-ID`; event traces include originating `request_id` when available.
