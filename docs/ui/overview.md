# UI Overview

The React + TypeScript + Vite UI exposes packages, versions, artifact observations, findings, impact paths, alerts, analyzer runs, auth, and settings.

## Local development

```sh
npm --prefix web install
npm --prefix web run generate:api
npm --prefix web run typecheck
npm --prefix web test -- --run
npm --prefix web run build
npm --prefix web run lint
```

The UI shell uses generated API types in `web/src/api/generated.ts`, an API client that sends cookies with requests, auth state from `/v1/auth/me`, and route placeholders for dashboard, packages, findings, impact, analyzer runs, and settings. Shared loading, error, and empty-state components are available under `web/src/components`.

UI copy should describe findings as signals, evidence, risk, or review-needed states unless deterministic API data explicitly supplies a stronger classification.
