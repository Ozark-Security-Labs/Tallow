-- name: UpsertFinding :one
INSERT INTO findings (
    id,
    run_id,
    rule_id,
    rule_version,
    analyzer_id,
    analyzer_version,
    ecosystem,
    package_name,
    version,
    artifact_id,
    snapshot_id,
    category,
    severity_hint,
    confidence,
    title,
    summary,
    subject_json,
    evidence_json,
    tags,
    status,
    created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
) ON CONFLICT (id) DO UPDATE SET
    run_id = EXCLUDED.run_id,
    rule_id = EXCLUDED.rule_id,
    rule_version = EXCLUDED.rule_version,
    analyzer_id = EXCLUDED.analyzer_id,
    analyzer_version = EXCLUDED.analyzer_version,
    ecosystem = EXCLUDED.ecosystem,
    package_name = EXCLUDED.package_name,
    version = EXCLUDED.version,
    artifact_id = EXCLUDED.artifact_id,
    snapshot_id = EXCLUDED.snapshot_id,
    category = EXCLUDED.category,
    severity_hint = EXCLUDED.severity_hint,
    confidence = EXCLUDED.confidence,
    title = EXCLUDED.title,
    summary = EXCLUDED.summary,
    subject_json = EXCLUDED.subject_json,
    evidence_json = EXCLUDED.evidence_json,
    tags = EXCLUDED.tags,
    updated_at = now()
RETURNING id, run_id, rule_id, rule_version, analyzer_id, analyzer_version, ecosystem, package_name, version, artifact_id, snapshot_id, category, severity_hint, confidence, title, summary, subject_json, evidence_json, tags, status, created_at, updated_at;

-- name: GetFinding :one
SELECT id, run_id, rule_id, rule_version, analyzer_id, analyzer_version, ecosystem, package_name, version, artifact_id, snapshot_id, category, severity_hint, confidence, title, summary, subject_json, evidence_json, tags, status, created_at, updated_at
FROM findings
WHERE id = $1;

-- name: ListFindings :many
SELECT id, run_id, rule_id, rule_version, analyzer_id, analyzer_version, ecosystem, package_name, version, artifact_id, snapshot_id, category, severity_hint, confidence, title, summary, subject_json, evidence_json, tags, status, created_at, updated_at
FROM findings
WHERE (sqlc.narg('ecosystem')::text IS NULL OR ecosystem = sqlc.narg('ecosystem'))
  AND (sqlc.narg('package_name')::text IS NULL OR package_name = sqlc.narg('package_name'))
  AND (sqlc.narg('version')::text IS NULL OR version = sqlc.narg('version'))
  AND (sqlc.narg('severity_hint')::text IS NULL OR severity_hint = sqlc.narg('severity_hint'))
  AND (sqlc.narg('confidence')::text IS NULL OR confidence = sqlc.narg('confidence'))
  AND (sqlc.narg('category')::text IS NULL OR category = sqlc.narg('category'))
  AND (sqlc.narg('rule_id')::text IS NULL OR rule_id = sqlc.narg('rule_id'))
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.narg('artifact_id')::text IS NULL OR artifact_id = sqlc.narg('artifact_id'))
  AND (sqlc.narg('snapshot_id')::text IS NULL OR snapshot_id = sqlc.narg('snapshot_id'))
  AND (sqlc.narg('created_after')::timestamptz IS NULL OR created_at >= sqlc.narg('created_after'))
  AND (sqlc.narg('created_before')::timestamptz IS NULL OR created_at <= sqlc.narg('created_before'))
  AND (
    sqlc.narg('cursor_created_at')::timestamptz IS NULL
    OR (created_at < sqlc.narg('cursor_created_at'))
    OR (created_at = sqlc.narg('cursor_created_at') AND id < sqlc.narg('cursor_id'))
  )
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit');
