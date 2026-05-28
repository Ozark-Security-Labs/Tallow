# Adapter Architecture

Tallow adapter interfaces isolate registries and SCM providers from analyzers, LLM enrichment, and policy code.

## Registry adapters

`internal/adapters/registry.Adapter` covers package identity normalization, package metadata, version metadata, artifact metadata, and registry hash claims. npm and PyPI conform through first-class wrappers around existing identity rules. Future Go module and Rust crates adapters should implement the same interface without coupling to analyzers or LLM packages.

Adapter outputs include provenance fields and raw metadata digests rather than unbounded raw blobs. Registry hash claims are represented on artifact metadata and must be verified by the artifact pipeline before they become deterministic evidence.

## SCM adapters

`internal/adapters/scm.Adapter` covers repository normalization, repository metadata, revision metadata, and bounded source evidence. GitHub conforms through the existing `internal/scm` normalization and GitHub adapter work. Future GitLab, Forgejo, and generic Git providers should map to these methods and return typed errors for unsupported or unimplemented operations.

## Adding an adapter

1. Implement the relevant interface in a provider-specific package.
2. Keep network methods bounded with timeouts, byte limits, and typed errors.
3. Preserve raw provider claims as evidence references or digests, not unbounded text.
4. Add fake/fixture contract tests and canonicalization tests.
5. Document production readiness and any unsupported future methods.
