-- name: InsertArtifact :one
INSERT INTO artifacts (
  version_id,
  artifact_type,
  filename,
  download_url,
  sha256,
  registry_digests_json,
  local_digests_json,
  verification_status,
  storage_uri,
  size_bytes,
  media_type,
  first_seen_at,
  last_seen_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id;
