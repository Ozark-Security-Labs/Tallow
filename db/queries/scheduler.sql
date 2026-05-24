-- name: ClaimDueJob :one
UPDATE scheduled_jobs SET lease_owner=$1, lease_until=now()+($2::text || ' seconds')::interval WHERE id=(SELECT id FROM scheduled_jobs WHERE next_run_at<=now() AND (lease_until IS NULL OR lease_until<now()) ORDER BY next_run_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id, kind, target, cadence_seconds, next_run_at, lease_owner, lease_until;
-- name: ReleaseJob :exec
UPDATE scheduled_jobs SET lease_owner=NULL, lease_until=NULL, next_run_at=$2 WHERE id=$1 AND lease_owner=$3;
