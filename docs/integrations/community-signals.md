# Community Signals

Community signals are contextual, low-authority inputs from public metadata. They can increase review priority but cannot prove compromise alone.

## Sources

Initial sources:
- Registry deprecation/yank status.
- Download count deltas where available.
- Maintainer/account changes from registry metadata.
- Repository archived/renamed/deleted status.
- Issue/advisory references when linked by registry or configured sources.

Future sources must be added behind adapters and stored with provenance.

## Signal fields

- `id`.
- `source_type`: `registry`, `scm`, `advisory`, `social`, `manual`.
- `source_name`.
- `package_id` and optional `version_id`.
- `signal_type`: `yanked`, `deprecated`, `maintainer_changed`, `repo_archived`, `downloads_anomaly`, `advisory_linked`, etc.
- `observed_at`.
- `source_observed_at` if available.
- `confidence`.
- `raw_evidence_uri` or bounded value.
- `url` optional.

## Scoring policy

- Community signals are modifiers, not primary deterministic findings unless they reflect registry state such as yanked/deprecated.
- Social posts and issue comments are untrusted text and must not be sent to LLM without prompt-injection handling.
- Download anomalies require baseline windows and must be labeled uncertain.

## Safety

- Do not scrape sites that prohibit it or require user credentials unless adapter terms are reviewed.
- Do not store personal data beyond what is necessary for package security context.
- Do not alert solely on maintainer identity changes without supporting policy.

## Tests

- Yanked/deprecated registry status creates contextual signal.
- Maintainer change between observations creates signal with old/new bounded values.
- Repeated observation of same status is idempotent.
- Untrusted issue text cannot alter LLM instructions.
