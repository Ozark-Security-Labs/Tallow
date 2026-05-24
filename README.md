<p align="center">
  <img src="docs/assets/tallow-banner.svg" alt="Tallow" width="640">
</p>

<p align="center"><strong>Self-hosted tripwire for malicious dependency releases.</strong></p>

<p align="center">
  <a href="https://github.com/Ozark-Security-Labs/Tallow/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Ozark-Security-Labs/Tallow/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/Ozark-Security-Labs/Tallow/actions/workflows/security.yml"><img alt="Security" src="https://github.com/Ozark-Security-Labs/Tallow/actions/workflows/security.yml/badge.svg?branch=main"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <img alt="Go" src="https://img.shields.io/badge/go-1.23%2B-00ADD8.svg?logo=go&logoColor=white">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB.svg?logo=python&logoColor=white">
  <img alt="NATS" src="https://img.shields.io/badge/NATS-event%20backbone-27AAE1.svg">
  <img alt="PostgreSQL" src="https://img.shields.io/badge/PostgreSQL-evidence%20store-4169E1.svg?logo=postgresql&logoColor=white">
</p>

---

Tallow watches the dependency versions your software can install, records what upstream registries actually published, validates registry hashes against local observations, deterministically analyzes package diffs, and alerts when a release behaves like a supply-chain attack.

It is **not just another CVE scanner**. Tallow is built for the uncomfortable window between a package release and a public advisory, when defenders need fast, explainable release intelligence for the dependencies they actually use.

Run it in your own infrastructure, point it at the packages and manifests that matter, and let Tallow light up the release events that should not pass silently.

## What Tallow does

- **Monitors dependency releases** across configured package ecosystems and repositories.
- **Correlates release signals** with your dependency inventory, lockfiles, SBOMs, and allowlists.
- **Scores suspicious change patterns** such as unusual publisher activity, package resurrection, metadata churn, new binary artifacts, and risky lifecycle hooks.
- **Preserves evidence** in PostgreSQL so every alert can be reviewed, suppressed, replayed, and audited.
- **Streams work through NATS** for resilient collectors, analyzers, enrichment jobs, and notification workers.
- **Runs self-hosted** so private dependency inventory and triage context stay under your control.

## Quickstart

> Tallow is under active development. The commands below show the intended public workflow and may change before the first tagged release.

Install the CLI from source:

```bash
go install github.com/Ozark-Security-Labs/Tallow/cmd/tallow@latest
```

Start local services:

```bash
cp configs/tallow.example.yml tallow.yml
docker compose up -d postgres nats
```

Initialize storage and add your first watch target:

```bash
tallow db migrate --config tallow.yml
tallow watch add pypi requests --config tallow.yml
tallow watch add npm @org/frontend --config tallow.yml
```

Run a one-shot collection and review alerts:

```bash
tallow collect --once --config tallow.yml
tallow analyze --since 24h --config tallow.yml
tallow alerts list --severity medium --config tallow.yml
tallow alerts explain alert_0001 --config tallow.yml
```

Run the worker stack:

```bash
tallow server --config tallow.yml
```

## Example CLI workflow

```bash
# Import dependency inventory from lockfiles or SBOMs
tallow inventory import ./go.sum --ecosystem go --project api
tallow inventory import ./requirements.lock --ecosystem pypi --project workers
tallow inventory import ./package-lock.json --ecosystem npm --project web

# Watch releases for packages present in inventory
tallow watch sync --from-inventory --project api --project workers --project web

# Inspect recent release activity
tallow releases list --since 7d
tallow releases show pypi:requests@2.32.0

# Explain why a release was flagged
tallow alerts explain alert_01JEXAMPLE --format markdown

# Export evidence for review or downstream tooling
tallow alerts export --format json --output tallow-alerts.json
tallow evidence export alert_01JEXAMPLE --output evidence.bundle.json
```

## Architecture overview

Tallow is designed as a small, inspectable surveillance pipeline:

1. **Inventory ingestion** reads lockfiles, SBOMs, repository manifests, and explicit watchlists.
2. **Collectors** poll package registries and release feeds for ecosystem-specific events.
3. **NATS subjects** carry normalized release events, enrichment requests, analyzer jobs, and alert notifications.
4. **Analyzers** apply deterministic rules and optional enrichment to produce scored release findings.
5. **PostgreSQL** stores packages, versions, artifacts, identities, evidence, suppressions, and alert state.
6. **CLI and API surfaces** support local triage, automation, CI integration, and future UI workflows.

```text
 lockfiles / SBOMs / watchlists
              |
              v
        tallow inventory
              |
              v
 package registries ---> collectors ---> NATS ---> analyzers ---> PostgreSQL
                                              |          |
                                              v          v
                                      notifications   CLI / API / exports
```

## Signal categories

Tallow focuses on release-time behaviors that are useful before advisory databases catch up:

- Publisher, maintainer, owner, or token-related changes.
- New or changed install scripts, build hooks, native binaries, or generated artifacts.
- Metadata drift in repository URLs, descriptions, license fields, links, and package names.
- Version anomalies including bursts, yanks, republish-like behavior, and unusual pre-releases.
- Dependency graph changes that introduce new transitive exposure.
- Provenance, signature, attestation, checksum, or source archive inconsistencies.
- Ecosystem-specific indicators that can be explained with raw evidence.

## Not just CVEs

CVE and advisory feeds are important, but they are retrospective. Tallow is meant to complement scanners such as Dependabot, OSV, Grype, Trivy, and commercial SCA platforms by watching the release stream itself.

Tallow asks different questions:

- Did a dependency you rely on publish something unusual today?
- Did package ownership, provenance, or artifact shape change unexpectedly?
- Did a low-noise watchlist package suddenly gain risky release characteristics?
- Can a reviewer see the exact evidence without trusting a black-box score?

## Configuration placeholder

```yaml
server:
  listen: "127.0.0.1:8844"

postgres:
  dsn: "postgres://tallow:tallow@localhost:5432/tallow?sslmode=disable"

nats:
  url: "nats://localhost:4222"

collectors:
  pypi:
    enabled: true
    interval: 5m
  npm:
    enabled: true
    interval: 5m
  go:
    enabled: true
    interval: 15m

analysis:
  min_severity: medium
  explain: true

notifications:
  stdout:
    enabled: true
```

## CI placeholder

Use Tallow in CI to compare dependency inventory changes against recent release intelligence:

```yaml
name: Tallow
on:
  pull_request:
  schedule:
    - cron: "17 * * * *"

permissions:
  contents: read

jobs:
  tallow:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ozark-Security-Labs/Tallow@v0
        with:
          config: tallow.yml
          inventory: "go.sum,requirements.lock,package-lock.json"
          mode: advisory
```

## Output formats

- **Markdown** for pull requests, issue comments, and human triage.
- **JSON** for automation, storage, replay, and downstream pipelines.
- **SARIF** for code-scanning style advisory surfacing where appropriate.
- **Evidence bundles** for audit trails and incident review.

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md) — installation and deployment options.
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — configuration reference.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — collectors, NATS subjects, analyzers, and storage model.
- [docs/development/implementation-sequence.md](docs/development/implementation-sequence.md) — canonical coding-agent implementation order.
- [docs/development/plans/README.md](docs/development/plans/README.md) — full milestone implementation plans for coding agents.
- [docs/development/testing-strategy.md](docs/development/testing-strategy.md) — required tests, fixtures, determinism gates, and release checks.
- [docs/architecture/package-identity.md](docs/architecture/package-identity.md) — canonical package coordinates and normalization.
- [docs/architecture/artifact-identity.md](docs/architecture/artifact-identity.md) — artifact identity, variants, and mutation semantics.
- [docs/architecture/hash-verification.md](docs/architecture/hash-verification.md) — registry hash validation and local observation policy.
- [docs/architecture/artifact-snapshots.md](docs/architecture/artifact-snapshots.md) — safe unpack manifests and deterministic diffs.
- [docs/analyzers/finding-schema.md](docs/analyzers/finding-schema.md) — deterministic finding fields, severity, confidence, and evidence references.
- [docs/analyzers/rule-authoring.md](docs/analyzers/rule-authoring.md) — writing built-in and future adapter-backed analyzer rules.
- [docs/integrations/adapters.md](docs/integrations/adapters.md) — registry, SCM, notification, and future adapter contracts.
- [docs/SIGNALS.md](docs/SIGNALS.md) — release signals and scoring rationale.
- [docs/CLI.md](docs/CLI.md) — command reference.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — running Tallow in production.
- [docs/SECURITY.md](docs/SECURITY.md) — threat model, hardening, and disclosure.

## Security model

Tallow is a defensive monitoring system. It should not execute untrusted dependency code, run package install scripts, or fetch artifacts in ways that trigger build hooks. Collectors and analyzers should prefer metadata, registry APIs, checksums, signatures, provenance documents, and static archive inspection.

If you believe you found a security issue in Tallow, please do not open a public issue. Follow the process in [SECURITY.md](SECURITY.md) or contact Ozark Security Labs through the repository security advisory workflow.

## Non-goals

- Replacing vulnerability databases, SCA tools, or SBOM generators.
- Proving that a package release is malicious.
- Automatically blocking all suspicious releases without review.
- Executing package code or install hooks to observe behavior.
- Becoming a general-purpose SIEM, EDR, or artifact sandbox.

Tallow is a release surveillance and evidence system: it helps defenders decide what deserves attention quickly.

## Contributing

Contributions are welcome, especially new ecosystem collectors, deterministic signal rules, documentation, deployment examples, and test fixtures.

Before opening a pull request:

```bash
go test ./...
python -m pytest
```

Please keep findings explainable, evidence-bound, and defensive. New signals should include examples, tests, and clear rationale so reviewers can understand why an alert fired.

## License

Tallow is licensed under the [Apache License 2.0](LICENSE).

### Foundation local configuration

Copy `.env.example` for local defaults. The API reads `TALLOW_*` variables including `TALLOW_POSTGRES_DSN`, `TALLOW_NATS_URL`, and `TALLOW_STORAGE_ROOT`.

### Security docs

Foundation security boundaries are documented in `docs/security/threat-model.md`, `docs/security/safe-unpack.md`, `docs/security/auth.md`, and `docs/security/llm-usage.md`.
