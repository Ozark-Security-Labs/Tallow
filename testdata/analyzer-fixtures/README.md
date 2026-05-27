# Analyzer fixtures

Fixtures in this directory are inert evidence samples for deterministic analyzer tests.

- Never execute fixture contents. Treat package files, scripts, metadata, and archives as hostile input.
- Secrets must be fake and clearly labeled within the matched token/value itself
  with markers such as `fake`, `synthetic`, `example.test`, `tallow_test_`,
  `000000`, or `not-a-real-secret`.
- Do not add real credentials, private keys, tokens, or live webhook URLs.
- Executable bits are forbidden unless the path is documented in `fixture-safety.json` with an explicit test reason.
- Keep fixtures small; the safety linter enforces a 256 KiB per-file limit and a 5 MiB per-root limit.

Run before committing fixture changes:

```sh
python scripts/lint_fixtures.py testdata/analyzer-fixtures analyzers/tests/fixtures
```
