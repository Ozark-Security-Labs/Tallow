-- name: UpsertDependencyIngestionRun :one
INSERT INTO dependency_ingestion_runs (source_kind, source_id, artifact_id, package_version_id, input_fingerprint, finished_at, edges_observed)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (source_kind, input_fingerprint) DO UPDATE SET finished_at=EXCLUDED.finished_at, edges_observed=EXCLUDED.edges_observed
RETURNING id;

-- name: UpsertDependencyEdge :one
INSERT INTO dependency_edges (parent_package_version_id, child_package_id, child_package_version_id, child_ecosystem, child_name_normalized, constraint_text, resolved_version, scope, relationship, is_optional, is_dev, is_build, confidence, source_type, manifest_path, lockfile_path, dependency_path, evidence_refs, edge_fingerprint, ingestion_run_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
ON CONFLICT (edge_fingerprint) DO UPDATE SET evidence_refs=EXCLUDED.evidence_refs, observed_at=now(), ingestion_run_id=EXCLUDED.ingestion_run_id
RETURNING id;

-- name: UpsertPackageVersionStatus :one
INSERT INTO package_version_statuses (package_version_id, status, source_finding_id, evidence_refs)
VALUES ($1,$2,$3,$4)
ON CONFLICT (package_version_id, status, source_finding_id) DO UPDATE SET evidence_refs=EXCLUDED.evidence_refs, updated_at=now()
RETURNING id;

-- name: UpsertTransitiveImpactStatus :one
INSERT INTO transitive_impact_statuses (affected_package_version_id, source_package_version_id, source_status_id, source_finding_id, status, depth, impact_path, path_fingerprint, evidence_refs)
VALUES ($1,$2,$3,$4,'affected_by_transitive',$5,$6,$7,$8)
ON CONFLICT (affected_package_version_id, source_finding_id, path_fingerprint) DO UPDATE SET impact_path=EXCLUDED.impact_path, evidence_refs=EXCLUDED.evidence_refs
RETURNING id;
