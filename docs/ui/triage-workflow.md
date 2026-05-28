# Triage Workflow

Tallow's UI presents findings as evidence-bound signals requiring review. It must not claim that a package is malicious unless deterministic server data explicitly provides that classification.

## Findings

The findings list supports filtering by ecosystem, package, severity, confidence, and status. Rows show package, version, severity, confidence, status, rule IDs, evidence count, and update context.

Finding detail shows rule metadata, package/version, severity, summary, safe evidence excerpts, and triage actions. Raw artifact content is not rendered unless the API marks the excerpt safe. Viewers see read-only state; analysts and admins can triage.

## Packages and artifacts

Package detail links versions, observations, analyzer runs, related findings, alerts, and artifact metadata. Artifact views emphasize hashes, size, source registry, and verification status; they do not execute packages or render raw content.

## Impact and alerts

Impact paths are shown only where graph data exists. A package affected by a transitive path is a review target and is not automatically labeled intrinsically compromised.

Alert detail shows severity, status, affected package/version, related findings, notification delivery attempts, and evidence links. Triage actions follow RBAC capabilities.
