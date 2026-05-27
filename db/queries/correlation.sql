-- name: InsertSourceCorrelation :one
INSERT INTO source_correlations (package_version_id, artifact_id, source_id, revision_id, confidence, evidence_refs, explanation)
VALUES ($1,$2,$3,$4,$5,$6,$7)
RETURNING id;
