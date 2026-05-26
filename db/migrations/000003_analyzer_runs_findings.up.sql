DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'findings'
          AND column_name = 'stable_id'
    ) THEN
        ALTER TABLE findings RENAME TO findings_legacy_000003;
    END IF;

    IF to_regclass('public.evidence_refs') IS NOT NULL THEN
        ALTER TABLE evidence_refs RENAME TO evidence_refs_legacy_000003;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS analyzer_runs (
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

CREATE INDEX IF NOT EXISTS analyzer_runs_status_idx ON analyzer_runs (status);
CREATE INDEX IF NOT EXISTS analyzer_runs_analyzer_id_idx ON analyzer_runs (analyzer_id);
CREATE INDEX IF NOT EXISTS analyzer_runs_started_at_idx ON analyzer_runs (started_at DESC);

CREATE TABLE IF NOT EXISTS findings (
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

CREATE INDEX IF NOT EXISTS findings_ecosystem_idx ON findings (ecosystem);
CREATE INDEX IF NOT EXISTS findings_package_name_idx ON findings (package_name);
CREATE INDEX IF NOT EXISTS findings_version_idx ON findings (version);
CREATE INDEX IF NOT EXISTS findings_severity_hint_idx ON findings (severity_hint);
CREATE INDEX IF NOT EXISTS findings_confidence_idx ON findings (confidence);
CREATE INDEX IF NOT EXISTS findings_status_idx ON findings (status);
CREATE INDEX IF NOT EXISTS findings_rule_id_idx ON findings (rule_id);
CREATE INDEX IF NOT EXISTS findings_artifact_id_idx ON findings (artifact_id);
CREATE INDEX IF NOT EXISTS findings_snapshot_id_idx ON findings (snapshot_id);
CREATE INDEX IF NOT EXISTS findings_created_at_id_idx ON findings (created_at DESC, id DESC);
