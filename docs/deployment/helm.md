# Helm deployment (experimental)

Helm support is experimental until validated in a real Kubernetes environment. Docker Compose remains the primary local deployment path.

## Required services

Tallow requires:

- Tallow API container.
- PostgreSQL for durable state.
- NATS JetStream for events/jobs.
- Filesystem or PVC-backed artifact storage.

## Compose to Helm values

| Docker Compose setting | Helm value |
| --- | --- |
| `TALLOW_SERVER_LISTEN=0.0.0.0:8844` | fixed in `templates/configmap.yaml` |
| `TALLOW_POSTGRES_DSN` | `postgres.existingSecret` + `postgres.secretKey` |
| `TALLOW_NATS_URL` | `nats.url` |
| `TALLOW_STORAGE_ROOT` | `storage.root` and PVC values |
| local bind storage | `storage.size` / `storage.storageClassName` |
| LLM disabled by omission | `llm.enabled=false` |
| community sharing disabled by omission | `communitySignals.sharing.enabled=false` |

## Secrets and storage assumptions

Secrets are referenced from existing Kubernetes Secrets. Do not put database passwords, API keys, webhook URLs, or LLM keys in `values.yaml`.

Filesystem storage uses a PVC mounted at `storage.root`. S3-compatible storage is a future deployment option.

## Secure defaults

The chart defaults to non-root execution, no privilege escalation, resource requests/limits, readiness/liveness probes, PVC storage, and a restrictive NetworkPolicy with no broad egress. Add explicit egress rules for registries, SCM providers, notification endpoints, or LLM/community endpoints after review.

LLM and community signal sharing are disabled by default. Enabling LLM requires explicit provider values and, for API providers, an existing secret. Enabling community sharing requires explicit organization and allowed classes.
