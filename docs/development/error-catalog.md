# Error catalog

Tallow APIs return `{"error":{"code","message","request_id","details"}}`. Codes: `validation_failed`, `auth_failed`, `hash_mismatch`, `unpack_rejected`, `analyzer_failed`, `registry_unavailable`, `database_unavailable`, `event_bus_unavailable`, `internal_error`, `not_implemented`. Logs may include request IDs and codes, never raw hostile payloads.
