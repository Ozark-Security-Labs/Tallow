# Tallow Implementation Plans

> **For Hermes/coding agents:** Use `subagent-driven-development` to execute these plans task-by-task. Each plan assumes a fresh agent with repository context plus the relevant issue body and linked docs.

These plans convert the Tallow milestones and hardening backlog into implementation-ready task sequences with files, tests, commands, gates, and issue coverage.

## Plans

1. [Foundation](01-foundation.md)
   - Covers repository/dev stack, Go API/CLI skeleton, PostgreSQL/sqlc, NATS, schemas, identity contracts, scheduler model, request IDs, typed errors, and self-protection gates.
   - Primary issues: #2-#8, #31-#40, #70, #85, #88.

2. [Artifact Observer](02-artifact-observer.md)
   - Covers npm/PyPI observation, artifact identity, storage URI rules, digest verification, safe unpack, snapshots, diffs, artifact events, and hot/warm/cold polling.
   - Primary issues: #9-#13, #41-#52, #71.

3. [Analyzer Engine](03-analyzer-engine.md)
   - Covers analyzer contracts, Python runtime, Go orchestration, deterministic finding schema, rule registry, finding IDs, evidence builder, initial rules, findings API, fixture safety, and network-off analyzer tests.
   - Primary issues: #14-#18, #53-#64, #86-#87.

4. [Dependency Graph + SCM](04-dependency-graph-scm.md)
   - Covers graph schema, dependency edge confidence, cycle-safe traversal, affected-by-transitive status, GitHub source adapter, SCM provider interface, and source correlation.
   - Primary issues: #19-#22, #65-#69.

5. [Alerts + UI](05-alerts-ui.md)
   - Covers auth provider abstraction, local auth, GitHub OAuth, RBAC, notification template schema, email/Teams templates, REST/OpenAPI, React+TS+Vite shell, triage views, and UI gates.
   - Primary issues: #23-#27, #72-#78.

6. [LLM + Ecosystem Expansion](06-llm-expansion.md)
   - Covers optional disabled-by-default LLM narrative, prompt schema, redaction, narrative output/persistence, prompt-injection fixtures, adapter interfaces, community signal opt-in, payload schema, and Helm planning.
   - Primary issues: #28-#30, #79-#84.

## Execution rules

- Start with plan 01. Do not start observers/analyzers before identity, event, storage, and schema contracts exist.
- Prefer one coding-agent task per plan task.
- Run the task-specific tests before broader milestone gates.
- If a task changes a public contract, update schemas, docs, examples, and generated artifacts in the same PR.
- If a task discovers a missing prerequisite, add/update a GitHub issue before implementing around it.
- Keep package contents, registry metadata, diffs, and README text as hostile evidence.
- Do not execute untrusted package code.
- Deterministic scoring owns canonical severity; LLM output remains optional narrative only.

## Recommended first sprint

1. Execute plan 01 tasks through package/artifact identity and event envelope schemas.
2. Implement PostgreSQL/sqlc and NATS helpers.
3. Implement storage URI builder and digest verifier from plan 02.
4. Only then start npm/PyPI observers and analyzer runtime.
