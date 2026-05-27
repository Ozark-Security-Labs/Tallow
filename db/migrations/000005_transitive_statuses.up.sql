CREATE TABLE IF NOT EXISTS package_version_statuses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  package_version_id UUID NOT NULL REFERENCES package_versions(id),
  status TEXT NOT NULL CHECK (status IN ('clean','suspicious','compromised_intrinsic','unknown','suppressed')),
  source_finding_id TEXT NOT NULL DEFAULT '',
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(package_version_id, status, source_finding_id)
);

CREATE TABLE IF NOT EXISTS transitive_impact_statuses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  affected_package_version_id UUID NOT NULL REFERENCES package_versions(id),
  source_package_version_id UUID NOT NULL REFERENCES package_versions(id),
  source_status_id UUID REFERENCES package_version_statuses(id),
  source_finding_id TEXT NOT NULL REFERENCES findings(id),
  status TEXT NOT NULL DEFAULT 'affected_by_transitive' CHECK (status = 'affected_by_transitive'),
  depth INT NOT NULL CHECK (depth > 0),
  impact_path JSONB NOT NULL,
  path_fingerprint TEXT NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(affected_package_version_id, source_finding_id, path_fingerprint)
);

CREATE INDEX IF NOT EXISTS transitive_impact_affected_idx ON transitive_impact_statuses(affected_package_version_id, depth, path_fingerprint);
