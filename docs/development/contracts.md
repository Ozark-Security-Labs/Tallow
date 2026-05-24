# Contract drift policy

Public contracts live under `schemas/`, `docs/api/openapi.yaml`, and generated database bindings. Contract changes must update schemas, valid/invalid golden fixtures under `schemas/testdata/`, and documentation together.

Run:

```sh
make schema-validate
make generate-check
```

If drift is reported, run `make generate`, commit regenerated files, and include fixtures that demonstrate the changed behavior.
