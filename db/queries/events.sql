-- name: CreateOutboxEvent :exec
INSERT INTO events_outbox (id, subject, payload) VALUES ($1,$2,$3) ON CONFLICT (id) DO NOTHING;
-- name: MarkOutboxPublished :exec
UPDATE events_outbox SET status='published', published_at=now() WHERE id=$1;
