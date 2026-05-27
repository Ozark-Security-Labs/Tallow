DROP TABLE IF EXISTS findings;

DROP TABLE IF EXISTS analyzer_runs;

DO $$
BEGIN
    IF to_regclass('public.findings_legacy_000003') IS NOT NULL THEN
        ALTER TABLE findings_legacy_000003 RENAME TO findings;
    END IF;

    IF to_regclass('public.evidence_refs_legacy_000003') IS NOT NULL THEN
        ALTER TABLE evidence_refs_legacy_000003 RENAME TO evidence_refs;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stable_id TEXT NOT NULL UNIQUE,
    artifact_id UUID REFERENCES artifacts (id),
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence_refs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID REFERENCES findings (id),
    artifact_id TEXT NOT NULL,
    path TEXT NOT NULL,
    start_line INT,
    end_line INT,
    start_byte BIGINT,
    end_byte BIGINT,
    hash TEXT,
    excerpt_redacted BOOLEAN NOT NULL DEFAULT true
);
