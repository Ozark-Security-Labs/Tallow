CREATE TABLE IF NOT EXISTS scm_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  external_id TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL UNIQUE,
  owner TEXT NOT NULL DEFAULT '',
  repo TEXT NOT NULL DEFAULT '',
  default_branch TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL DEFAULT 'unknown',
  last_indexed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS scm_revisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id UUID NOT NULL REFERENCES scm_sources(id),
  revision TEXT NOT NULL,
  revision_type TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  UNIQUE(source_id, revision, revision_type)
);
CREATE TABLE IF NOT EXISTS source_manifests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id UUID NOT NULL REFERENCES scm_sources(id),
  path TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  manifest_type TEXT NOT NULL,
  commit_sha TEXT NOT NULL DEFAULT '',
  parsed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(source_id, path, commit_sha)
);
CREATE TABLE IF NOT EXISTS source_correlations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  package_version_id UUID REFERENCES package_versions(id),
  artifact_id UUID REFERENCES artifacts(id),
  source_id UUID REFERENCES scm_sources(id),
  revision_id UUID REFERENCES scm_revisions(id),
  confidence TEXT NOT NULL CHECK (confidence IN ('exact_metadata','release_tag_match','repository_metadata','manifest_observed','inferred_name','conflicting','unknown')),
  score INT NOT NULL DEFAULT 0 CHECK (score >= 0 AND score <= 100),
  conflicting_source_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  reason TEXT NOT NULL DEFAULT '',
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  explanation TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
