CREATE TABLE IF NOT EXISTS dependency_ingestion_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('registry','source','sbom','manual')),
  source_id UUID,
  artifact_id UUID REFERENCES artifacts(id),
  package_version_id UUID REFERENCES package_versions(id),
  input_fingerprint TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  edges_observed INT NOT NULL DEFAULT 0,
  UNIQUE(source_kind, input_fingerprint)
);

CREATE TABLE IF NOT EXISTS dependency_edges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_package_version_id UUID NOT NULL REFERENCES package_versions(id),
  child_package_id UUID NOT NULL REFERENCES packages(id),
  child_package_version_id UUID REFERENCES package_versions(id),
  child_ecosystem TEXT NOT NULL,
  child_name_normalized TEXT NOT NULL,
  constraint_text TEXT NOT NULL DEFAULT '',
  resolved_version TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL DEFAULT 'runtime' CHECK (scope IN ('runtime','dev','optional','peer','build','test','unknown')),
  relationship TEXT NOT NULL CHECK (relationship IN ('direct','transitive')),
  is_optional BOOLEAN NOT NULL DEFAULT false,
  is_dev BOOLEAN NOT NULL DEFAULT false,
  is_build BOOLEAN NOT NULL DEFAULT false,
  confidence TEXT NOT NULL CHECK (confidence IN ('resolved_lockfile','declared_metadata','inferred')),
  source_type TEXT NOT NULL CHECK (source_type IN ('lockfile','manifest','sbom','registry_metadata','manual')),
  manifest_path TEXT NOT NULL DEFAULT '',
  lockfile_path TEXT NOT NULL DEFAULT '',
  dependency_path JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  edge_fingerprint TEXT NOT NULL UNIQUE,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ingestion_run_id UUID REFERENCES dependency_ingestion_runs(id)
);

CREATE INDEX IF NOT EXISTS dependency_edges_child_version_idx ON dependency_edges(child_package_version_id, relationship, scope);
CREATE INDEX IF NOT EXISTS dependency_edges_parent_idx ON dependency_edges(parent_package_version_id);
