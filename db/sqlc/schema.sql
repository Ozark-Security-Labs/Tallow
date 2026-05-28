CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem TEXT NOT NULL,
    registry_url TEXT NOT NULL,
    raw_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ecosystem, registry_url, normalized_name)
);

CREATE TABLE package_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id UUID NOT NULL REFERENCES packages (id),
    raw_version TEXT NOT NULL,
    normalized_version TEXT NOT NULL,
    normalization_status TEXT NOT NULL DEFAULT 'normalized',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (package_id, normalized_version)
);

CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_id UUID NOT NULL REFERENCES package_versions (id),
    artifact_type TEXT NOT NULL,
    filename TEXT NOT NULL,
    download_url TEXT NOT NULL,
    sha256 TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    registry_digests_json TEXT NOT NULL DEFAULT '{}',
    local_digests_json TEXT NOT NULL DEFAULT '{}',
    verification_status TEXT NOT NULL DEFAULT 'pending',
    storage_uri TEXT NOT NULL DEFAULT '',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    media_type TEXT NOT NULL DEFAULT '',
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ
);

CREATE TABLE artifact_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts (id),
    source TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    evidence_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE events_outbox (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    retry_count INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ
);

CREATE TABLE events_inbox (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_subject TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scheduled_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    cadence_seconds INT NOT NULL CHECK (cadence_seconds >= 60),
    next_run_at TIMESTAMPTZ NOT NULL,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, target)
);

CREATE TABLE analyzer_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE,
    analyzer_id TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    ruleset_version TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    duration_ms BIGINT,
    input_json JSONB NOT NULL,
    output_json JSONB,
    error_json JSONB
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analyzer_runs (id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    analyzer_id TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version TEXT,
    artifact_id TEXT,
    snapshot_id TEXT,
    category TEXT NOT NULL,
    severity_hint TEXT NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    subject_json JSONB NOT NULL,
    evidence_json JSONB NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE dependency_ingestion_runs (
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

CREATE TABLE dependency_edges (
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

CREATE TABLE package_version_statuses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_version_id UUID NOT NULL REFERENCES package_versions(id),
    status TEXT NOT NULL CHECK (status IN ('clean','suspicious','compromised_intrinsic','unknown','suppressed')),
    source_finding_id TEXT NOT NULL DEFAULT '',
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(package_version_id, status, source_finding_id)
);

CREATE TABLE transitive_impact_statuses (
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

CREATE TABLE scm_sources (
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

CREATE TABLE scm_revisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES scm_sources(id),
    revision TEXT NOT NULL,
    revision_type TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE(source_id, revision, revision_type)
);

CREATE TABLE source_manifests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES scm_sources(id),
    path TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    manifest_type TEXT NOT NULL,
    commit_sha TEXT NOT NULL DEFAULT '',
    parsed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(source_id, path, commit_sha)
);

CREATE TABLE source_correlations (
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
CREATE TABLE user_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(provider, provider_subject)
);

CREATE TABLE user_credentials (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL DEFAULT 'bcrypt',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (password_hash LIKE 'bcrypt$%')
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(user_id, role)
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ
);

CREATE TABLE oauth_states (
    nonce_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    redirect_path TEXT NOT NULL DEFAULT '/',
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    finding_id TEXT REFERENCES findings(id),
    package_name TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved','suppressed','reopened')),
    title TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notification_routes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('email','teams')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    severity_threshold TEXT NOT NULL DEFAULT 'medium',
    filters_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notification_deliveries (
    id TEXT PRIMARY KEY,
    route_id TEXT REFERENCES notification_routes(id),
    alert_id TEXT REFERENCES alerts(id),
    finding_id TEXT REFERENCES findings(id),
    channel TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','sent','failed')),
    attempts INT NOT NULL DEFAULT 1,
    sanitized_error TEXT NOT NULL DEFAULT '',
    provider_message_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at TIMESTAMPTZ
);
