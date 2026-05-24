# Coding Agent Handoff

This document gives implementation agents enough context to begin work without re-litigating architecture.

## Start here

1. Read `README.md`.
2. Read `AGENTS.md`.
3. Read `docs/architecture/overview.md`.
4. Read the issue assigned to you and all linked docs.
5. Keep work small, test-covered, and evidence-bound.

## Implementation priorities

1. Foundation repo/tooling.
2. Go API/CLI skeleton.
3. Postgres migrations and sqlc.
4. NATS event envelope and publisher/consumer helpers.
5. npm/PyPI artifact observers and hash validation.
6. Safe unpack + artifact snapshots.
7. Analyzer contract and Python runtime.
8. Deterministic rules.
9. Dependency graph and transitive propagation.
10. Auth, notifications, and UI.

## Rules of the road

- Do not execute untrusted package code.
- Do not send package contents to LLMs unless explicit narrative enrichment is enabled and redaction policy applies.
- Keep public schemas versioned.
- Keep event payloads small and reference stored artifacts/evidence.
- Add fixtures for registry/analyzer edge cases.
- Update docs with any public contract change.

## Milestone implementation plans

Full implementation plans live in `docs/development/plans/README.md`. Coding agents should follow those plans in order and treat each task as an implementation unit with its own tests and verification gates.
