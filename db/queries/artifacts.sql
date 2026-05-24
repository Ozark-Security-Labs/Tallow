-- name: InsertArtifact :one
INSERT INTO artifacts (version_id, artifact_type, filename, download_url, sha256) VALUES ($1,$2,$3,$4,$5) RETURNING id;
