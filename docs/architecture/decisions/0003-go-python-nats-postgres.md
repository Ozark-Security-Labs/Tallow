# ADR 0003: Go + Python + NATS JetStream + PostgreSQL

Go owns the control plane and CLI. Python owns analyzers. NATS JetStream is the durable event bus. PostgreSQL is the source of truth. Erlang/Elixir is deferred; service boundaries remain swappable if scale later warrants BEAM.
