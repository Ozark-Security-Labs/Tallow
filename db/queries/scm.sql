-- name: UpsertSCMSource :one
INSERT INTO scm_sources (provider, external_id, url, owner, repo, default_branch, visibility, last_indexed_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (url) DO UPDATE SET default_branch=EXCLUDED.default_branch, visibility=EXCLUDED.visibility, last_indexed_at=EXCLUDED.last_indexed_at
RETURNING id;
