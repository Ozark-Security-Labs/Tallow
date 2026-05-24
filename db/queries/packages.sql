-- name: UpsertPackage :one
INSERT INTO packages (ecosystem, registry_url, raw_name, normalized_name, namespace) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (ecosystem, registry_url, normalized_name) DO UPDATE SET raw_name=EXCLUDED.raw_name RETURNING id;
-- name: UpsertPackageVersion :one
INSERT INTO package_versions (package_id, raw_version, normalized_version, normalization_status) VALUES ($1,$2,$3,$4) ON CONFLICT (package_id, normalized_version) DO UPDATE SET raw_version=EXCLUDED.raw_version RETURNING id;
