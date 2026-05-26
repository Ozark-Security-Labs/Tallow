-- name: InsertAnalyzerRun :one
INSERT INTO analyzer_runs (
    id,
    job_id,
    analyzer_id,
    analyzer_version,
    ruleset_version,
    status,
    started_at,
    finished_at,
    duration_ms,
    input_json,
    output_json,
    error_json
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
) ON CONFLICT (job_id) DO UPDATE SET
    status = EXCLUDED.status,
    finished_at = EXCLUDED.finished_at,
    duration_ms = EXCLUDED.duration_ms,
    output_json = EXCLUDED.output_json,
    error_json = EXCLUDED.error_json
RETURNING id, job_id, analyzer_id, analyzer_version, ruleset_version, status, started_at, finished_at, duration_ms, input_json, output_json, error_json;

-- name: GetAnalyzerRunByJobID :one
SELECT id, job_id, analyzer_id, analyzer_version, ruleset_version, status, started_at, finished_at, duration_ms, input_json, output_json, error_json
FROM analyzer_runs
WHERE job_id = $1;
