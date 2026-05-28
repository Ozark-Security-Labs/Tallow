-- name: InsertSourceCorrelation :one
INSERT INTO source_correlations (package_version_id, artifact_id, source_id, revision_id, confidence, score, conflicting_source_ids, reason, evidence_refs, explanation)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING id;


-- name: ListSourceCorrelationsByPackageVersion :many
SELECT id, package_version_id, artifact_id, source_id, revision_id, confidence, score, conflicting_source_ids, reason, evidence_refs, explanation, created_at
FROM source_correlations
WHERE package_version_id = $1
ORDER BY confidence, score DESC, created_at DESC, id DESC
LIMIT $2 OFFSET $3;

-- name: ListSourceCorrelationsByArtifact :many
SELECT id, package_version_id, artifact_id, source_id, revision_id, confidence, score, conflicting_source_ids, reason, evidence_refs, explanation, created_at
FROM source_correlations
WHERE artifact_id = $1
ORDER BY confidence, score DESC, created_at DESC, id DESC
LIMIT $2 OFFSET $3;
