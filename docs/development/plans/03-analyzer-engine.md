# Analyzer Engine Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build Tallow's deterministic analyzer engine milestone: schema-backed analyzer contracts, Python analyzer runtime, stable finding/evidence helpers, initial built-in rules, Go orchestration and findings persistence/API, plus CI safety gates for no-network analyzer tests and fixture hygiene.

**Architecture:** Go remains the control plane: it prepares analyzer jobs from persisted artifact/snapshot data, invokes Python analyzers with bounded resources, validates JSON input/output contracts, persists analyzer runs and findings, and exposes findings through REST. Python remains the analyzer runtime: it reads already-unpacked snapshots and optional diff metadata, never executes package code, runs deterministic rules, and emits evidence-bound findings sorted into canonical order.

**Tech Stack:** Go, PostgreSQL migrations/queries, OpenAPI 3.1, Python 3.12, uv, ruff, pytest, jsonschema, optional esprima/tree-sitter later only if justified by tests, GitHub Actions.

**Issues covered:** #14, #15, #16, #17, #18, #53, #54, #55, #56, #57, #58, #59, #60, #61, #62, #63, #64, #86, #87.

---

## Non-negotiable invariants

- Do not execute package code, lifecycle scripts, setup.py, binaries, or test fixtures.
- Do not import Python or JavaScript modules from unpacked artifacts.
- Do not perform outbound network from analyzer code or analyzer tests.
- Treat package files, metadata, diffs, README text, and fixture content as hostile input.
- Findings are evidence records, not prose reports.
- Stable finding IDs must exclude timestamps, random data, hostnames, map iteration order, and analyzer runtime process details.
- Analyzer output order must be stable across repeated runs on the same input.
- Every rule must have positive, negative, boundary, prompt-injection, and determinism tests where applicable.
- Go policy later owns canonical severity; analyzers emit `severity_hint` only.

---

## Current repository baseline

Existing relevant files:

- `AGENTS.md`
- `docs/development/implementation-sequence.md`
- `docs/development/testing-strategy.md`
- `docs/security/no-execution-policy.md`
- `docs/analyzers/contract.md`
- `docs/analyzers/finding-schema.md`
- `docs/analyzers/rule-authoring.md`
- `docs/analyzers/builtin-rules.md`
- `docs/architecture/analyzer-engine.md`
- `docs/api/openapi.yaml`
- `schemas/analyzer-input.schema.json`
- `schemas/analyzer-output.schema.json`

Existing directories to extend or create:

- `analyzers/`
- `cmd/tallow/`
- `cmd/tallow-api/`
- `internal/`
- `schemas/`
- `scripts/`
- `.github/workflows/`
- `testdata/`

Current schema files are placeholders and must be replaced with strict contract definitions.

---

## Milestone completion gates

Run these from repository root `/home/srvadmin/workspace/ozark-security-labs/Tallow` before considering the milestone complete:

```bash
go test ./...
uv run --project analyzers pytest
uv run --project analyzers ruff check
python scripts/validate_schemas.py
python scripts/lint_fixtures.py testdata/analyzer-fixtures analyzers/tests/fixtures
TALLOW_ANALYZER_NETWORK_OFF=1 uv run --project analyzers pytest tests
```

Expected final result:

- All commands pass.
- `git status --short` shows only intentional changes.
- Re-running the analyzer twice on fixture inputs produces byte-identical canonical JSON after excluding `started_at`, `finished_at`, and duration fields.
- CI runs Go, Python, schema validation, fixture linting, and network-off analyzer tests.

---

## Task 1: Replace analyzer contract schemas with strict v1 contracts (#14)

**Objective:** Define authoritative JSON Schemas for analyzer input/output and deterministic findings.

**Files:**

- Modify: `schemas/analyzer-input.schema.json`
- Modify: `schemas/analyzer-output.schema.json`
- Create: `schemas/finding.schema.json`
- Create: `schemas/examples/analyzer-input.snapshot-diff.npm.json`
- Create: `schemas/examples/analyzer-output.findings.npm.json`
- Modify: `docs/analyzers/contract.md`
- Modify: `docs/analyzers/finding-schema.md`

**Implementation details:**

`schemas/analyzer-input.schema.json` must require:

- `contract_version`: constant `v1`
- `job_id`: non-empty string
- `analysis_type`: enum `snapshot`, `snapshot_diff`, `hash_verification`
- `subject`: object containing:
  - `ecosystem`: enum `npm`, `pypi`
  - `package_name`: string
  - `version`: string, optional for diff jobs if `to_version` is present
  - `from_version`: string or null
  - `to_version`: string or null
  - `package_id`: string or null
  - `artifact_id`: string or null
  - `snapshot_id`: string or null
- `artifacts`: object with optional `from` and `to`, each containing `artifact_id`, `sha256`, `filename`, `size_bytes`, `snapshot_path`
- `snapshot_refs`: object with optional `from` and `to`; each ref must include `snapshot_id`, `root`, `manifest_path`
- `hash_verification`: optional object for hash mismatch inputs
- `options`: object with `enabled_rules`, `disabled_rules`, `max_file_bytes`, `max_findings_per_rule`, `allow_binary_packages`

`schemas/finding.schema.json` must require:

- `schema_version`
- `id`
- `rule_id`
- `rule_version`
- `analyzer_id`
- `analyzer_version`
- `subject`
- `title`
- `summary`
- `category`
- `severity_hint`
- `confidence`
- `evidence`
- `tags`
- `created_at`

Use enums from `docs/analyzers/finding-schema.md` for `category`, `severity_hint`, `confidence`, and evidence `kind`.

`schemas/analyzer-output.schema.json` must require:

- `contract_version`: constant `v1`
- `job_id`
- `analyzer`: object with `id`, `version`, `ruleset_version`
- `status`: enum `ok`, `failed`
- `findings`: array of `$ref` to `finding.schema.json`
- `errors`: array, required but may be empty
- `metrics`: object with deterministic counters only

Set `additionalProperties: false` for all stable contract objects unless a field is explicitly reserved as metadata.

**Tests and verification:**

- Add schema examples under `schemas/examples/`.
- Add `scripts/validate_schemas.py` to validate every `schemas/examples/*.json` against the matching schema.
- Run:

```bash
python scripts/validate_schemas.py
```

Expected: all examples validate.

**Commit:**

```bash
git add schemas docs/analyzers scripts/validate_schemas.py
git commit -m "feat: define analyzer contract schemas"
```

---

## Task 2: Create Python analyzer workspace (#15)

**Objective:** Add a uv-managed Python workspace with ruff and pytest configured.

**Files:**

- Create: `analyzers/pyproject.toml`
- Create: `analyzers/README.md`
- Create: `analyzers/tallow_analyzer_sdk/__init__.py`
- Create: `analyzers/tallow_analyzer_sdk/contracts.py`
- Create: `analyzers/tallow_analyzer_sdk/paths.py`
- Create: `analyzers/tallow_analyzer_sdk/redaction.py`
- Create: `analyzers/tallow_analyzer_sdk/canonical_json.py`
- Create: `analyzers/tests/test_contracts.py`

**Implementation details:**

`analyzers/pyproject.toml`:

- Project name: `tallow-analyzers`
- Python: `>=3.12`
- Runtime dependencies: `jsonschema`
- Dev dependencies: `pytest`, `ruff`
- Ruff line length: `100`
- Pytest test path: `tests`

`contracts.py` should expose:

- `load_schema(name: str) -> dict`
- `validate_analyzer_input(payload: dict) -> None`
- `validate_analyzer_output(payload: dict) -> None`
- `ValidationError` re-export or wrapper

Schemas must be loaded from repository `schemas/` using a path relative to `analyzers/` and should not require network access for `$ref` resolution.

**Tests and verification:**

Write tests that:

- Valid example input validates.
- Missing required field fails.
- Valid example output validates.
- Output with missing evidence fails.

Run:

```bash
uv run --project analyzers pytest tests/test_contracts.py -v
uv run --project analyzers ruff check
```

Expected: tests and ruff pass.

**Commit:**

```bash
git add analyzers
uv lock --project analyzers
git add analyzers/uv.lock
git commit -m "feat: add python analyzer runtime workspace"
```

---

## Task 3: Implement canonical JSON and deterministic sorting helpers (#15, #54)

**Objective:** Provide a single canonical serialization path for finding IDs and deterministic output comparisons.

**Files:**

- Modify: `analyzers/tallow_analyzer_sdk/canonical_json.py`
- Create: `analyzers/tests/test_canonical_json.py`

**Implementation details:**

Implement:

- `canonical_dumps(value: Any) -> str` using sorted keys, compact separators, UTF-8, no NaN.
- `canonical_sha256(value: Any) -> str` returning lowercase hex SHA-256 over canonical JSON bytes.
- `sort_findings(findings: list[dict]) -> list[dict]` using severity rank, `rule_id`, first evidence path, first evidence range, then `id`.
- `strip_runtime_fields(payload: dict) -> dict` for tests only, removing timestamps and duration-like metrics.

**Tests and verification:**

Tests must prove:

- Dictionaries with different key order hash identically.
- Lists preserve order and therefore hash differently when order differs.
- `sort_findings` is stable across shuffled input.

Run:

```bash
uv run --project analyzers pytest tests/test_canonical_json.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/tallow_analyzer_sdk/canonical_json.py analyzers/tests/test_canonical_json.py
git commit -m "feat: add canonical analyzer json helpers"
```

---

## Task 4: Implement deterministic finding ID builder (#54)

**Objective:** Build stable finding IDs from rule, subject, and normalized evidence, independent of runtime ordering.

**Files:**

- Create: `analyzers/tallow_analyzer_sdk/finding_id.py`
- Create: `analyzers/tests/test_finding_id.py`
- Modify: `docs/analyzers/finding-schema.md`

**Implementation details:**

Implement:

- `normalize_subject_for_id(subject: dict) -> dict`
- `normalize_evidence_for_id(evidence: list[dict]) -> list[dict]`
- `build_finding_id(schema_version: str, rule_id: str, subject: dict, evidence: list[dict]) -> str`

ID format:

```text
fin_v1_<32 lowercase hex chars>
```

Hash input fields:

- `schema_version`
- `rule_id`
- normalized subject stable keys:
  - `ecosystem`
  - `package_name`
  - `version` or `to_version`
  - `artifact_id`, if present
  - `snapshot_id`, if present
  - `from_artifact_id` and `to_artifact_id`, if present
- normalized evidence keys:
  - `kind`
  - `artifact_id`
  - `snapshot_id`
  - `path`
  - `start_line`
  - `end_line`
  - `start_byte`
  - `end_byte`
  - `value_hash` rather than raw `value` when `value` is long or sensitive

Sort normalized evidence by `kind`, `path`, numeric ranges, `value_hash` before hashing.

**Tests and verification:**

Tests must prove:

- Same inputs produce same ID across repeated calls.
- Evidence list order does not change ID.
- Timestamp-like fields do not affect ID.
- Changing rule ID changes ID.
- Changing evidence path or range changes ID.

Run:

```bash
uv run --project analyzers pytest tests/test_finding_id.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/tallow_analyzer_sdk/finding_id.py analyzers/tests/test_finding_id.py docs/analyzers/finding-schema.md
git commit -m "feat: add deterministic finding id builder"
```

---

## Task 5: Implement evidence builder helper (#55)

**Objective:** Centralize path normalization, coordinate validation, redaction, and evidence object construction.

**Files:**

- Create: `analyzers/tallow_analyzer_sdk/evidence.py`
- Modify: `analyzers/tallow_analyzer_sdk/paths.py`
- Modify: `analyzers/tallow_analyzer_sdk/redaction.py`
- Create: `analyzers/tests/test_evidence.py`

**Implementation details:**

Implement path normalization rules:

- Reject absolute paths.
- Reject empty paths.
- Reject paths containing `..` after POSIX normalization.
- Convert backslashes to `/` for evidence paths.
- Strip leading `./`.
- Never resolve against host filesystem for logical evidence paths.

Implement evidence builders:

- `file_evidence(path, *, snapshot_id=None, artifact_id=None, start_line=None, end_line=None, start_byte=None, end_byte=None, snippet=None, description)`
- `metadata_evidence(key, value, *, description)`
- `hash_evidence(algorithm, observed, claimed=None, *, description)`
- `binary_evidence(path, magic, size_bytes, sha256, *, description)`

Redaction defaults:

- Replace token-like values with `<redacted:sha256:12hex>`.
- Redact URL query strings.
- Bound snippets to 240 characters.
- Preserve enough context to prove a match without storing full secrets.

**Tests and verification:**

Tests must cover:

- Absolute paths rejected.
- `../escape` rejected.
- Windows separators normalized.
- Line and byte ranges validate start <= end.
- Snippets are redacted and bounded.
- Metadata evidence hashes secret-like values.

Run:

```bash
uv run --project analyzers pytest tests/test_evidence.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/tallow_analyzer_sdk/evidence.py analyzers/tallow_analyzer_sdk/paths.py analyzers/tallow_analyzer_sdk/redaction.py analyzers/tests/test_evidence.py
git commit -m "feat: add analyzer evidence builder"
```

---

## Task 6: Implement rule metadata registry (#53)

**Objective:** Provide deterministic rule discovery, validation, filtering, and duplicate ID protection.

**Files:**

- Create: `analyzers/tallow_analyzer_sdk/rules.py`
- Create: `analyzers/rules/__init__.py`
- Create: `analyzers/rules/registry.py`
- Create: `analyzers/tests/test_rule_registry.py`
- Modify: `docs/analyzers/rule-authoring.md`
- Modify: `docs/analyzers/builtin-rules.md`

**Implementation details:**

Define:

- `RuleMetadata` dataclass:
  - `rule_id`
  - `version`
  - `name`
  - `description`
  - `category`
  - `ecosystems`
  - `default_severity_hint`
  - `default_confidence`
  - `inputs`
  - `tags`
- `Rule` protocol:
  - `metadata: RuleMetadata`
  - `evaluate(context: AnalysisContext) -> Iterable[FindingDraft]`
- `RuleRegistry`:
  - `register(rule)`
  - `all()` sorted by `rule_id`
  - `enabled_for(ecosystem, enabled_rules=None, disabled_rules=None)` sorted by `rule_id`
  - duplicate `rule_id` raises `ValueError`

Rule ID naming convention:

- Built-in IDs use `<ecosystem-or-artifact>.<family>.<signal>`.
- Examples:
  - `npm.lifecycle.install_script`
  - `npm.lifecycle.network_command`
  - `js.secrets.env_token_access`
  - `js.obfuscation.eval_decode_chain`
  - `pypi.setup.exec_call`
  - `py.obfuscation.decode_exec_chain`
  - `network.webhook_url`
  - `artifact.binary.unexpected`
  - `artifact.entropy.high_blob`

**Tests and verification:**

Tests must prove:

- Duplicate rule IDs fail.
- Registry lists rules in deterministic order.
- Ecosystem filtering works.
- Enabled/disabled rule options work.

Run:

```bash
uv run --project analyzers pytest tests/test_rule_registry.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/tallow_analyzer_sdk/rules.py analyzers/rules docs/analyzers analyzers/tests/test_rule_registry.py
git commit -m "feat: add analyzer rule registry"
```

---

## Task 7: Add analyzer context, snapshot walking, and finding builder (#15, #17)

**Objective:** Provide reusable bounded file traversal and finding construction for all rules.

**Files:**

- Create: `analyzers/tallow_analyzer_sdk/context.py`
- Create: `analyzers/tallow_analyzer_sdk/files.py`
- Create: `analyzers/tallow_analyzer_sdk/finding.py`
- Create: `analyzers/tests/test_context_files.py`
- Create: `analyzers/tests/fixtures/snapshots/simple_npm/package/package.json`

**Implementation details:**

`AnalysisContext` must include:

- parsed analyzer input
- subject
- ecosystem
- snapshot roots for `from` and `to`
- options
- deterministic clock provider for tests

File walking must:

- Walk only under declared snapshot root.
- Sort paths bytewise after normalized relative path conversion.
- Skip files over `max_file_bytes` unless a rule explicitly consumes metadata only.
- Never follow symlinks.
- Provide helpers:
  - `iter_files(globs=None, include_binary=False)`
  - `read_text(path)` with safe decoding and replacement
  - `read_bytes(path, max_bytes)`
  - `line_span_for_offset(text, start, end)`

Finding builder must:

- Accept rule metadata, subject, evidence, title, summary, optional severity/confidence overrides.
- Call deterministic ID builder.
- Sort tags.
- Populate analyzer ID/version from a central constant.

**Tests and verification:**

Tests must cover:

- Traversal sorted order.
- Symlink skipped if fixture platform supports symlink creation.
- Oversized file skipped.
- Finding builder emits valid schema output with evidence.

Run:

```bash
uv run --project analyzers pytest tests/test_context_files.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/tallow_analyzer_sdk analyzers/tests/fixtures analyzers/tests/test_context_files.py
git commit -m "feat: add analyzer context and finding builder"
```

---

## Task 8: Add analyzer CLI entrypoint and example analyzer (#15, #17)

**Objective:** Add a runnable Python analyzer that reads JSON input and emits contract-valid JSON output.

**Files:**

- Create: `analyzers/tallow_analyzers/__init__.py`
- Create: `analyzers/tallow_analyzers/cli.py`
- Create: `analyzers/tallow_analyzers/main.py`
- Create: `analyzers/tests/test_cli.py`
- Modify: `analyzers/pyproject.toml`

**Implementation details:**

Expose console script:

```text
tallow-analyzer = "tallow_analyzers.cli:main"
```

CLI behavior:

- Accept `--input PATH` or read stdin when omitted.
- Accept `--output PATH` or write stdout when omitted.
- Accept `--list-rules` to emit sorted rule metadata JSON.
- Validate input before evaluating rules.
- Run registry-enabled rules.
- Validate output before writing.
- On rule exception, continue only if `options.fail_fast` is false; include deterministic `errors` entries.
- Exit non-zero for invalid input or invalid output.

**Tests and verification:**

Tests must cover:

- `--list-rules` output sorted.
- Valid empty fixture produces `status: ok` and `findings: []`.
- Invalid input exits non-zero.
- Running the same fixture twice produces equivalent output after stripping runtime fields.

Run:

```bash
uv run --project analyzers pytest tests/test_cli.py -v
uv run --project analyzers python -m tallow_analyzers.cli --list-rules
```

Expected: tests pass and rule list is valid JSON.

**Commit:**

```bash
git add analyzers/tallow_analyzers analyzers/tests/test_cli.py analyzers/pyproject.toml
git commit -m "feat: add analyzer cli entrypoint"
```

---

## Task 9: Implement npm lifecycle script rule (#56)

**Objective:** Detect lifecycle scripts in `package.json` without executing them.

**Files:**

- Create: `analyzers/rules/npm_lifecycle.py`
- Create: `analyzers/tests/rules/test_npm_lifecycle.py`
- Create fixtures under:
  - `testdata/analyzer-fixtures/npm/lifecycle_absent/`
  - `testdata/analyzer-fixtures/npm/lifecycle_benign/`
  - `testdata/analyzer-fixtures/npm/lifecycle_suspicious/`
- Modify: `analyzers/rules/registry.py`
- Modify: `docs/analyzers/builtin-rules.md`

**Implementation details:**

Rule metadata:

- `rule_id`: `npm.lifecycle.install_script`
- `category`: `script`
- `default_severity_hint`: `medium`
- `default_confidence`: `high`
- `ecosystems`: `npm`

Detection:

- Parse `package.json` as JSON.
- Inspect only `scripts` keys: `preinstall`, `install`, `postinstall`, `prepublish`, `prepare`.
- Emit evidence pointing to the exact key/value when line coordinates can be computed.
- Summary must include script key, not unbounded script value.

**Tests and verification:**

Tests must cover:

- No `scripts` produces no finding.
- Non-lifecycle scripts produce no finding.
- `postinstall` produces one finding.
- Prompt-injection text in package description does not affect output.
- Determinism across repeated runs.

Run:

```bash
uv run --project analyzers pytest tests/rules/test_npm_lifecycle.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/rules/npm_lifecycle.py analyzers/rules/registry.py analyzers/tests/rules/test_npm_lifecycle.py testdata/analyzer-fixtures/npm docs/analyzers/builtin-rules.md
git commit -m "feat: add npm lifecycle analyzer rule"
```

---

## Task 10: Implement npm lifecycle network command rule (#57)

**Objective:** Detect network-capable commands inside npm lifecycle scripts.

**Files:**

- Create: `analyzers/rules/npm_network_script.py`
- Create: `analyzers/tests/rules/test_npm_network_script.py`
- Add fixtures under `testdata/analyzer-fixtures/npm/network_script_*`
- Modify: `analyzers/rules/registry.py`
- Modify: `docs/analyzers/builtin-rules.md`

**Implementation details:**

Rule metadata:

- `rule_id`: `npm.lifecycle.network_command`
- `category`: `network`
- `default_severity_hint`: `high`
- `default_confidence`: `high`

Detect in lifecycle script values only:

- `curl`
- `wget`
- `nc`
- `netcat`
- `powershell`
- `Invoke-WebRequest`
- `iwr`
- `fetch(` inside `node -e` snippets when easily detectable

Handle shell quoting variants with deterministic regex tokenization. Do not scan README prose or arbitrary docs.

**Tests and verification:**

Run:

```bash
uv run --project analyzers pytest tests/rules/test_npm_network_script.py -v
```

Expected: positive curl/wget/powershell fixtures trigger; README-only text does not.

**Commit:**

```bash
git add analyzers/rules/npm_network_script.py analyzers/rules/registry.py analyzers/tests/rules/test_npm_network_script.py testdata/analyzer-fixtures/npm docs/analyzers/builtin-rules.md
git commit -m "feat: detect npm lifecycle network commands"
```

---

## Task 11: Implement JS env/token access rule (#58)

**Objective:** Detect suspicious environment token and local credential access in JavaScript files.

**Files:**

- Create: `analyzers/rules/js_env_token.py`
- Create: `analyzers/tests/rules/test_js_env_token.py`
- Add fixtures under `testdata/analyzer-fixtures/js/env_token_*`
- Modify: `analyzers/rules/registry.py`

**Implementation details:**

Rule metadata:

- `rule_id`: `js.secrets.env_token_access`
- `category`: `credential`
- `default_severity_hint`: `high`
- `default_confidence`: `medium`

Detection:

- Candidate files: `.js`, `.mjs`, `.cjs`, `.ts` excluding `.d.ts`.
- Detect `process.env.<TOKENLIKE>` and `process.env["TOKENLIKE"]` where key contains `TOKEN`, `SECRET`, `KEY`, `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_`, `CI_JOB_TOKEN`.
- Detect reads of `.npmrc`, `.ssh/`, `id_rsa`, `known_hosts` in executable JS contexts.
- Prefer simple parse/token masking if parser dependency is introduced; otherwise deterministic line scanner with lower confidence for ambiguous matches.
- Redact token-like literals in snippets.

**Tests and verification:**

Tests must cover:

- Positive env access.
- Positive `.npmrc` read.
- Comments and README prose do not trigger where feasible.
- Token literal redacted.

Run:

```bash
uv run --project analyzers pytest tests/rules/test_js_env_token.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/rules/js_env_token.py analyzers/rules/registry.py analyzers/tests/rules/test_js_env_token.py testdata/analyzer-fixtures/js
git commit -m "feat: detect javascript credential access"
```

---

## Task 12: Implement JS eval/decode obfuscation rule (#59)

**Objective:** Detect decode-to-execution chains in JavaScript.

**Files:**

- Create: `analyzers/rules/js_eval_decode.py`
- Create: `analyzers/tests/rules/test_js_eval_decode.py`
- Add fixtures under `testdata/analyzer-fixtures/js/eval_decode_*`
- Modify: `analyzers/rules/registry.py`

**Implementation details:**

Rule metadata:

- `rule_id`: `js.obfuscation.eval_decode_chain`
- `category`: `obfuscation`
- `default_severity_hint`: `high`
- `default_confidence`: `high` only when decode source and execution sink are present

Detect chains such as:

- `eval(atob(...))`
- `Function(atob(...))()`
- `eval(Buffer.from(..., 'base64').toString())`
- `setTimeout(decodedString)` where decoded string is derived from base64, lower confidence

Benign base64 constants without execution sink must not trigger high confidence and should usually not trigger at all.

**Tests and verification:**

Run:

```bash
uv run --project analyzers pytest tests/rules/test_js_eval_decode.py -v
```

Expected: malicious chain fixture triggers; benign base64 fixture does not.

**Commit:**

```bash
git add analyzers/rules/js_eval_decode.py analyzers/rules/registry.py analyzers/tests/rules/test_js_eval_decode.py testdata/analyzer-fixtures/js
git commit -m "feat: detect javascript decode eval chains"
```

---

## Task 13: Implement PyPI setup execution rule (#61)

**Objective:** Detect execution sinks in Python packaging setup files.

**Files:**

- Create: `analyzers/rules/pypi_setup_exec.py`
- Create: `analyzers/tests/rules/test_pypi_setup_exec.py`
- Add fixtures under `testdata/analyzer-fixtures/pypi/setup_exec_*`
- Modify: `analyzers/rules/registry.py`

**Implementation details:**

Rule metadata:

- `rule_id`: `pypi.setup.exec_call`
- `category`: `script`
- `default_severity_hint`: `high`
- `default_confidence`: `high`

Candidate files:

- `setup.py`
- `setup.cfg`
- `pyproject.toml` only for suspicious dynamic build-backend references or command hooks in this MVP

For `setup.py`, parse with Python `ast` and detect:

- `os.system(...)`
- `subprocess.call/run/Popen/check_call/check_output(...)`
- `eval(...)`
- `exec(...)`
- suspicious custom `cmdclass` methods invoking execution sinks

Evidence must cite AST line numbers.

**Tests and verification:**

Run:

```bash
uv run --project analyzers pytest tests/rules/test_pypi_setup_exec.py -v
```

Expected: malicious setup fixture triggers; safe declarative setup fixture does not.

**Commit:**

```bash
git add analyzers/rules/pypi_setup_exec.py analyzers/rules/registry.py analyzers/tests/rules/test_pypi_setup_exec.py testdata/analyzer-fixtures/pypi
git commit -m "feat: detect pypi setup execution sinks"
```

---

## Task 14: Implement Python decode-exec rule (#62)

**Objective:** Detect Python decode/decompress/unmarshal chains flowing to execution sinks.

**Files:**

- Create: `analyzers/rules/py_decode_exec.py`
- Create: `analyzers/tests/rules/test_py_decode_exec.py`
- Add fixtures under `testdata/analyzer-fixtures/pypi/decode_exec_*`
- Modify: `analyzers/rules/registry.py`

**Implementation details:**

Rule metadata:

- `rule_id`: `py.obfuscation.decode_exec_chain`
- `category`: `obfuscation`
- `default_severity_hint`: `high`
- `default_confidence`: `high` when decode/decompress and execution sink are present

Use `ast` to detect:

- `exec(base64.b64decode(...))`
- `eval(base64.b64decode(...))`
- `exec(zlib.decompress(...))`
- `marshal.loads(...)` feeding `exec`, `eval`, `types.FunctionType`, or import execution

Benign encoded test data with no execution sink must not trigger.

**Tests and verification:**

Run:

```bash
uv run --project analyzers pytest tests/rules/test_py_decode_exec.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/rules/py_decode_exec.py analyzers/rules/registry.py analyzers/tests/rules/test_py_decode_exec.py testdata/analyzer-fixtures/pypi
git commit -m "feat: detect python decode exec chains"
```

---

## Task 15: Implement webhook/exfil URL rule (#63)

**Objective:** Detect webhook and exfiltration-oriented URLs in executable package paths.

**Files:**

- Create: `analyzers/rules/webhook_url.py`
- Create: `analyzers/tests/rules/test_webhook_url.py`
- Add fixtures under `testdata/analyzer-fixtures/shared/webhook_*`
- Modify: `analyzers/rules/registry.py`

**Implementation details:**

Rule metadata:

- `rule_id`: `network.webhook_url`
- `category`: `network`
- `default_severity_hint`: `high`
- `default_confidence`: `medium`

Detect URLs containing:

- `discord.com/api/webhooks/`
- `discordapp.com/api/webhooks/`
- `api.telegram.org/bot`
- `hooks.slack.com/services/`
- `webhook.site/`
- `pastebin.com/raw/`
- `gist.githubusercontent.com/`

Executable path heuristics:

- High/medium confidence in `.js`, `.ts`, `.py`, shell scripts, `package.json` lifecycle scripts, `setup.py`.
- Low confidence or ignore by default in `README`, `CHANGELOG`, docs, examples, markdown.
- Redact query strings and bot tokens.

**Tests and verification:**

Run:

```bash
uv run --project analyzers pytest tests/rules/test_webhook_url.py -v
```

Expected: executable file triggers; README-only fixture ignored or lower confidence per documented behavior.

**Commit:**

```bash
git add analyzers/rules/webhook_url.py analyzers/rules/registry.py analyzers/tests/rules/test_webhook_url.py testdata/analyzer-fixtures/shared
git commit -m "feat: detect webhook urls in executable package files"
```

---

## Task 16: Implement unexpected binary artifact rule (#60)

**Objective:** Detect newly added native binaries unless explicitly allowed for known binary packages.

**Files:**

- Create: `analyzers/rules/unexpected_binary.py`
- Create: `analyzers/tests/rules/test_unexpected_binary.py`
- Add fixtures under `testdata/analyzer-fixtures/shared/binary_*`
- Modify: `analyzers/rules/registry.py`
- Modify: `docs/analyzers/builtin-rules.md`

**Implementation details:**

Rule metadata:

- `rule_id`: `artifact.binary.unexpected`
- `category`: `binary`
- `default_severity_hint`: `medium`
- `default_confidence`: `high`

Detect magic bytes:

- ELF: `7f 45 4c 46`
- PE: `4d 5a`
- Mach-O: `fe ed fa ce`, `fe ed fa cf`, `cf fa ed fe`, `ca fe ba be`

Only emit for files present in the `to` snapshot but not the `from` snapshot for diff jobs. For single snapshot jobs, emit unless package is allowlisted.

Allowlist input:

- `options.allow_binary_packages`: array of ecosystem/name strings or package names for MVP.

Evidence must include:

- path
- magic/type
- size
- SHA-256 hash only, not binary content

**Tests and verification:**

Run:

```bash
uv run --project analyzers pytest tests/rules/test_unexpected_binary.py -v
```

Expected: suspicious binary triggers; allowlisted package does not.

**Commit:**

```bash
git add analyzers/rules/unexpected_binary.py analyzers/rules/registry.py analyzers/tests/rules/test_unexpected_binary.py testdata/analyzer-fixtures/shared docs/analyzers/builtin-rules.md
git commit -m "feat: detect unexpected binary artifacts"
```

---

## Task 17: Implement high entropy blob rule (#64)

**Objective:** Detect newly added high-entropy blobs without storing blob contents.

**Files:**

- Create: `analyzers/rules/high_entropy_blob.py`
- Create: `analyzers/tests/rules/test_high_entropy_blob.py`
- Add fixtures under `testdata/analyzer-fixtures/shared/high_entropy_*`
- Modify: `analyzers/rules/registry.py`

**Implementation details:**

Rule metadata:

- `rule_id`: `artifact.entropy.high_blob`
- `category`: `obfuscation`
- `default_severity_hint`: `medium`
- `default_confidence`: `medium`

Algorithm:

- Candidate files newly added in `to` snapshot or all files in single snapshot mode.
- Ignore lockfiles, known binary files, images, archives, minified vendor bundles unless executable context suggests otherwise.
- Scan bounded windows, e.g. 512+ bytes.
- Compute Shannon entropy.
- Emit if entropy >= configured threshold, default `7.2`, and length >= configured minimum, default `512` bytes.
- Evidence includes path, entropy rounded to 3 decimals, length, SHA-256 hash of blob/window, and byte range.
- Do not store full blob.

**Tests and verification:**

Run:

```bash
uv run --project analyzers pytest tests/rules/test_high_entropy_blob.py -v
```

Expected: suspicious blob triggers; lockfile/minified benign fixture does not.

**Commit:**

```bash
git add analyzers/rules/high_entropy_blob.py analyzers/rules/registry.py analyzers/tests/rules/test_high_entropy_blob.py testdata/analyzer-fixtures/shared
git commit -m "feat: detect high entropy blobs"
```

---

## Task 18: Add cross-rule analyzer fixture integration tests (#17)

**Objective:** Prove the full Python analyzer CLI emits deterministic, schema-valid findings across npm and PyPI fixture sets.

**Files:**

- Create: `analyzers/tests/test_analyzer_integration.py`
- Create: `testdata/analyzer-fixtures/inputs/npm-malicious-diff.json`
- Create: `testdata/analyzer-fixtures/inputs/pypi-malicious-snapshot.json`
- Create: `testdata/analyzer-fixtures/expected/npm-malicious-diff.output.json`
- Create: `testdata/analyzer-fixtures/expected/pypi-malicious-snapshot.output.json`

**Implementation details:**

Tests should:

- Run CLI in-process or subprocess against input fixture.
- Validate output against `schemas/analyzer-output.schema.json`.
- Strip runtime fields.
- Compare canonical JSON to expected fixture.
- Run twice and assert byte-identical canonical JSON.

Do not make expected files brittle on `created_at`; either use fixed clock via option `options.fixed_created_at` in test inputs or strip runtime fields before comparison.

**Verification:**

Run:

```bash
uv run --project analyzers pytest tests/test_analyzer_integration.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/tests/test_analyzer_integration.py testdata/analyzer-fixtures
git commit -m "test: add analyzer integration fixtures"
```

---

## Task 19: Implement Go analyzer package contracts and schema validation (#16)

**Objective:** Add Go-side types and schema validation for analyzer input/output.

**Files:**

- Create: `internal/analyzers/types.go`
- Create: `internal/analyzers/schema.go`
- Create: `internal/analyzers/schema_test.go`
- Create: `internal/analyzers/testdata/valid_input.json`
- Create: `internal/analyzers/testdata/valid_output.json`
- Create: `internal/analyzers/testdata/invalid_output_missing_evidence.json`

**Implementation details:**

Define Go structs matching the schemas:

- `AnalyzerInput`
- `AnalyzerOutput`
- `AnalyzerInfo`
- `Finding`
- `FindingEvidence`
- `AnalyzerError`
- `AnalyzerMetrics`

Use a JSON Schema validation library already present if any exists. If no Go module exists yet, create `go.mod` first with module path from repository conventions. If adding a new dependency, keep it minimal and document why in commit message.

Schema validation must load local schema files from `schemas/` and resolve local refs without network.

**Tests and verification:**

Run:

```bash
go test ./internal/analyzers -run TestSchemaValidation -v
```

Expected: valid fixtures pass; invalid fixture fails.

**Commit:**

```bash
git add internal/analyzers go.mod go.sum
git commit -m "feat: add go analyzer contract validation"
```

---

## Task 20: Implement Go analyzer executor with timeout and failure isolation (#16)

**Objective:** Invoke configured analyzer commands safely and validate their output.

**Files:**

- Create: `internal/analyzers/executor.go`
- Create: `internal/analyzers/executor_test.go`
- Create: `internal/analyzers/testdata/fake_analyzer_ok.py`
- Create: `internal/analyzers/testdata/fake_analyzer_invalid.py`
- Create: `internal/analyzers/testdata/fake_analyzer_sleep.py`

**Implementation details:**

Executor API:

- `type Executor struct { Command []string; Timeout time.Duration; WorkDir string; Env []string }`
- `func (e *Executor) Run(ctx context.Context, input AnalyzerInput) (AnalyzerOutput, RunResult, error)`

Required behavior:

- Serialize input to analyzer stdin or temp input file; choose one convention and document it.
- Capture stdout/stderr with size limits.
- Enforce context timeout.
- Validate output schema before returning success.
- Return structured errors for invalid JSON, schema failure, non-zero exit, and timeout.
- Do not crash worker loop on analyzer failure.

Environment:

- Set `TALLOW_ANALYZER_NETWORK_OFF=1` in tests.
- Do not inherit credentials by default. Start with minimal env: `PATH`, `PYTHONPATH` if required, `TALLOW_*` only.

**Tests and verification:**

Run:

```bash
go test ./internal/analyzers -run TestExecutor -v
```

Expected: success, invalid output, non-zero exit, and timeout paths pass.

**Commit:**

```bash
git add internal/analyzers/executor.go internal/analyzers/executor_test.go internal/analyzers/testdata
git commit -m "feat: add analyzer executor"
```

---

## Task 21: Add analyzer run and finding persistence model (#16, #18)

**Objective:** Persist analyzer runs and stable findings with idempotent natural keys.

**Files:**

- Create: `db/migrations/0005_analyzer_runs_findings.sql`
- Create: `db/queries/findings.sql`
- Create: `internal/findings/model.go`
- Create: `internal/findings/store.go`
- Create: `internal/findings/store_test.go`

**Implementation details:**

Migration should create:

`analyzer_runs`:

- `id` primary key, preferably ULID/text generated by Go or database default
- `job_id` unique
- `analyzer_id`
- `analyzer_version`
- `ruleset_version`
- `status`
- `started_at`
- `finished_at`
- `duration_ms`
- `input_json`
- `output_json`
- `error_json`
- indexes on `status`, `analyzer_id`, `started_at`

`findings`:

- `id` primary key, stable analyzer finding ID
- `run_id` references `analyzer_runs(id)`
- `rule_id`
- `rule_version`
- `analyzer_id`
- `analyzer_version`
- `ecosystem`
- `package_name`
- `version`
- `artifact_id`
- `snapshot_id`
- `category`
- `severity_hint`
- `confidence`
- `title`
- `summary`
- `subject_json`
- `evidence_json`
- `tags` text array or jsonb
- `status` default `open`
- `created_at`
- `updated_at`
- unique primary key on `id`
- indexes for ecosystem/package/version/severity/confidence/status/rule_id

Store behavior:

- Insert analyzer run.
- Upsert findings by stable `id`.
- Replayed analyzer output must not duplicate findings.
- Preserve latest run reference or add a separate join table if historical run-to-finding relation is required. MVP can update `run_id` to latest run but must document this.

**Tests and verification:**

Use existing repository database test pattern. If none exists yet, create store tests with a test database helper and skip unless `TALLOW_TEST_DATABASE_URL` is set.

Run:

```bash
go test ./internal/findings -v
```

Expected: filter and idempotency tests pass or integration DB tests skip with clear message when no database URL is set.

**Commit:**

```bash
git add db/migrations db/queries internal/findings
git commit -m "feat: persist analyzer runs and findings"
```

---

## Task 22: Implement analyzer worker orchestration skeleton (#16)

**Objective:** Connect persisted artifact/snapshot events to analyzer input preparation, execution, validation, persistence, and completion events.

**Files:**

- Create: `internal/workers/analyzer_worker.go`
- Create: `internal/workers/analyzer_worker_test.go`
- Modify: `docs/architecture/analyzer-engine.md`
- Modify: `docs/architecture/events.md`

**Implementation details:**

Worker responsibilities:

- Consume artifact/snapshot-ready event type used by earlier phases. If not implemented yet, define an internal interface and fake event in tests.
- Load package/artifact/snapshot metadata from store interfaces.
- Build `AnalyzerInput` with local snapshot refs.
- Call `internal/analyzers.Executor`.
- Persist run and findings through `internal/findings.Store`.
- Publish `tallow.analysis.completed` or `tallow.analysis.failed` after persistence.
- Retry behavior must be bounded and idempotent.

Tests must cover:

- Success path persists run/findings and publishes completed event.
- Invalid analyzer output persists failed run and publishes failed event.
- Timeout persists failed run and does not panic.
- Replayed event does not duplicate findings.

**Verification:**

```bash
go test ./internal/workers -run TestAnalyzerWorker -v
```

Expected: pass.

**Commit:**

```bash
git add internal/workers docs/architecture/analyzer-engine.md docs/architecture/events.md
git commit -m "feat: add analyzer worker orchestration"
```

---

## Task 23: Expose findings API (#18)

**Objective:** Add REST endpoints for querying findings with filters and pagination.

**Files:**

- Create: `internal/api/findings.go`
- Create: `internal/api/findings_test.go`
- Modify: `docs/api/openapi.yaml`
- Modify: `docs/api/README.md`

**Implementation details:**

Endpoints:

- `GET /v1/findings`
- `GET /v1/findings/{id}`

`GET /v1/findings` filters:

- `ecosystem`
- `package`
- `version`
- `severity_hint`
- `confidence`
- `category`
- `rule_id`
- `status`
- `artifact_id`
- `snapshot_id`
- `created_after`
- `created_before`
- `limit`
- `cursor`

Pagination:

- Default limit: 50
- Max limit: 200
- Cursor should be stable, based on `(created_at, id)` or repository's existing pagination convention.
- Empty results return `items: []` and no error.

Response shape:

- `items`: array of finding summaries including evidence count and tags
- `next_cursor`: string or null

`GET /v1/findings/{id}` returns full subject/evidence JSON.

**Tests and verification:**

Tests must cover:

- Empty results.
- Filter by ecosystem/package/version.
- Filter by severity/confidence/status.
- Pagination returns deterministic order.
- Unknown ID returns 404.

Run:

```bash
go test ./internal/api -run TestFindings -v
```

Expected: pass.

**Commit:**

```bash
git add internal/api/findings.go internal/api/findings_test.go docs/api/openapi.yaml docs/api/README.md
git commit -m "feat: expose findings api"
```

---

## Task 24: Add fixture safety linter (#86)

**Objective:** Prevent unsafe or misleading analyzer fixtures from entering the repository.

**Files:**

- Create: `scripts/lint_fixtures.py`
- Create: `scripts/tests/test_lint_fixtures.py`
- Create: `testdata/analyzer-fixtures/README.md`
- Modify: `docs/development/testing-strategy.md`

**Implementation details:**

Fixture linter rules:

- Enforce per-file max size, default 256 KiB unless allowlisted in `testdata/analyzer-fixtures/.fixture-allowlist.yml`.
- Reject likely real secrets:
  - GitHub tokens
  - npm tokens
  - AWS access keys
  - private key headers unless marked fake
  - Slack/Discord/Telegram tokens unless fake/redacted
- Allow fake secrets only if containing `FAKE`, `EXAMPLE`, `TEST`, or documented in allowlist.
- Reject executable bits unless allowlisted with reason.
- Reject archive files over max size unless allowlisted.
- Print deterministic sorted findings.
- Exit non-zero on violation.

`testdata/analyzer-fixtures/README.md` must explain:

- Fixtures are inert and must never be executed.
- Secrets must be fake and clearly labeled.
- Executable bits require allowlist reason.

**Tests and verification:**

Run:

```bash
python -m pytest scripts/tests/test_lint_fixtures.py -v
python scripts/lint_fixtures.py testdata/analyzer-fixtures analyzers/tests/fixtures
```

Expected: tests pass and linter reports no violations.

**Commit:**

```bash
git add scripts/lint_fixtures.py scripts/tests/test_lint_fixtures.py testdata/analyzer-fixtures/README.md docs/development/testing-strategy.md
git commit -m "feat: add analyzer fixture safety linter"
```

---

## Task 25: Add network-off analyzer test mode (#87)

**Objective:** Make analyzer tests fail on any attempted outbound network access.

**Files:**

- Create: `analyzers/tests/conftest.py`
- Create: `analyzers/tests/test_network_off.py`
- Modify: `docs/security/no-execution-policy.md`
- Modify: `docs/development/testing-strategy.md`

**Implementation details:**

When `TALLOW_ANALYZER_NETWORK_OFF=1`:

- Monkeypatch Python `socket.socket.connect`, `socket.create_connection`, and common urllib/http client paths to raise `AssertionError`.
- Allow no outbound exceptions for MVP.
- Keep local file IO unaffected.
- Keep schema loading local-only.
- Ensure failures are explicit: `Outbound network disabled for analyzer tests`.

Add test:

- A deliberate `socket.create_connection(("example.com", 80))` inside a test fails with expected message when env var set.
- Analyzer CLI fixture runs successfully with network-off mode enabled.

**Verification:**

```bash
TALLOW_ANALYZER_NETWORK_OFF=1 uv run --project analyzers pytest tests/test_network_off.py tests/test_cli.py -v
```

Expected: pass.

**Commit:**

```bash
git add analyzers/tests/conftest.py analyzers/tests/test_network_off.py docs/security/no-execution-policy.md docs/development/testing-strategy.md
git commit -m "test: add network-off analyzer mode"
```

---

## Task 26: Add CI jobs for schemas, Python analyzers, Go, fixture lint, and network-off mode (#14, #15, #16, #86, #87)

**Objective:** Enforce analyzer milestone safety and determinism in CI.

**Files:**

- Create or modify: `.github/workflows/ci.yml`
- Modify: `README.md` or `docs/development/local-setup.md` if command list changes

**Implementation details:**

CI jobs:

- `schemas`:
  - Set up Python.
  - Run `python scripts/validate_schemas.py`.
- `python-analyzers`:
  - Install uv.
  - Run `uv run --project analyzers ruff check`.
  - Run `uv run --project analyzers pytest`.
- `python-analyzers-network-off`:
  - Run `TALLOW_ANALYZER_NETWORK_OFF=1 uv run --project analyzers pytest tests`.
- `fixture-safety`:
  - Run `python scripts/lint_fixtures.py testdata/analyzer-fixtures analyzers/tests/fixtures`.
- `go`:
  - Run `go test ./...`.

If the repository already has CI, extend it instead of creating duplicate workflows.

**Verification:**

Run locally:

```bash
python scripts/validate_schemas.py
uv run --project analyzers ruff check
uv run --project analyzers pytest
TALLOW_ANALYZER_NETWORK_OFF=1 uv run --project analyzers pytest tests
python scripts/lint_fixtures.py testdata/analyzer-fixtures analyzers/tests/fixtures
go test ./...
```

Expected: all pass.

**Commit:**

```bash
git add .github/workflows/ci.yml README.md docs/development/local-setup.md
git commit -m "ci: add analyzer engine safety gates"
```

---

## Task 27: Add docs cross-links and limitations (#14, #17, #18, #53-#64, #86, #87)

**Objective:** Keep public docs aligned with implemented contracts and known MVP limitations.

**Files:**

- Modify: `docs/analyzers/contract.md`
- Modify: `docs/analyzers/finding-schema.md`
- Modify: `docs/analyzers/rule-authoring.md`
- Modify: `docs/analyzers/builtin-rules.md`
- Modify: `docs/architecture/analyzer-engine.md`
- Modify: `docs/api/README.md`
- Modify: `docs/security/no-execution-policy.md`
- Modify: `docs/development/testing-strategy.md`
- Modify: `docs/development/implementation-sequence.md`

**Required documentation content:**

- Analyzer contract compatibility rules:
  - Additive optional fields are minor-compatible.
  - Removing required fields or changing ID inputs requires new contract version.
  - Rule detection logic changes require `rule_version` bump.
- Analyzer limitations:
  - MVP rules are static heuristics, not malware execution or sandbox detonation.
  - JavaScript AST coverage may fall back to bounded string scanning where parser support is unavailable.
  - Binary rule detects magic bytes, not full reverse engineering.
  - High entropy is a signal requiring review, not proof of malice.
- Findings API pagination and filter semantics.
- CI safety gates and fixture safety rules.

**Verification:**

Run any docs lint if configured. If not configured, run:

```bash
git diff --check
```

Expected: no trailing whitespace or conflict markers.

**Commit:**

```bash
git add docs
git commit -m "docs: document analyzer engine contracts and limitations"
```

---

## Task 28: Final milestone verification and issue closure checklist

**Objective:** Prove all covered issues meet acceptance criteria and prepare PR summary.

**Files:**

- Modify only if verification exposes gaps.

**Verification commands:**

```bash
python scripts/validate_schemas.py
uv run --project analyzers ruff check
uv run --project analyzers pytest
TALLOW_ANALYZER_NETWORK_OFF=1 uv run --project analyzers pytest tests
python scripts/lint_fixtures.py testdata/analyzer-fixtures analyzers/tests/fixtures
go test ./...
git diff --check
git status --short
```

Expected:

- All test and lint commands pass.
- No unintended files in `git status --short`.

**Issue acceptance mapping:**

- #14:
  - Strict schemas exist for input, output, and findings.
  - Examples validate in CI.
  - Contract compatibility rules documented.
- #15:
  - `uv run --project analyzers pytest` passes.
  - `uv run --project analyzers ruff check` passes.
  - SDK validates schema payloads.
  - Finding ID helper exists.
  - CLI example analyzer exists.
- #16:
  - Go executor validates input/output schemas.
  - Worker handles success, invalid output, timeout, and failure.
  - Runs persisted with timings/status.
- #17:
  - Initial deterministic rules implemented with npm and PyPI fixtures.
  - Findings include severity/confidence/evidence/rationale.
  - Output deterministic across reruns.
- #18:
  - Findings persisted by stable ID.
  - REST filters and pagination implemented.
  - OpenAPI updated.
- #53:
  - Rule metadata registry validates metadata and duplicate IDs.
  - Enabled rules listing works.
- #54:
  - Finding IDs deterministic and ordering-independent.
- #55:
  - Evidence builder rejects unsafe paths and redacts snippets by default.
- #56:
  - npm lifecycle rule detects lifecycle scripts and exact evidence.
- #57:
  - npm network command rule detects curl/wget/nc/powershell variants in scripts.
- #58:
  - JS env/token rule detects token-like env and credential path reads.
- #59:
  - JS eval/decode rule detects decode plus execution chains.
- #60:
  - Unexpected binary rule detects ELF/PE/Mach-O and supports allowlist.
- #61:
  - PyPI setup execution rule detects setup execution sinks.
- #62:
  - Python decode-exec rule detects decode/decompress/unmarshal to execution.
- #63:
  - Webhook URL rule detects suspicious webhook/exfil URLs and redacts query/token material.
- #64:
  - High entropy rule reports entropy/length/path/hash only.
- #86:
  - Fixture safety linter enforces size, fake-secret, and executable-bit rules in CI.
- #87:
  - Network-off analyzer tests fail on outbound attempts and run in CI.

**Final PR summary template:**

```markdown
## Summary

- Added strict analyzer input/output/finding schemas and local schema validation.
- Added uv/ruff/pytest Python analyzer runtime, SDK helpers, deterministic finding IDs, evidence builder, and rule registry.
- Implemented initial deterministic built-in rules for npm, JavaScript, PyPI, webhook URLs, binaries, and high entropy blobs.
- Added Go analyzer executor/worker/persistence and findings API.
- Added CI gates for schemas, Python analyzers, Go tests, fixture safety linting, and network-off analyzer mode.

## Verification

- [ ] `python scripts/validate_schemas.py`
- [ ] `uv run --project analyzers ruff check`
- [ ] `uv run --project analyzers pytest`
- [ ] `TALLOW_ANALYZER_NETWORK_OFF=1 uv run --project analyzers pytest tests`
- [ ] `python scripts/lint_fixtures.py testdata/analyzer-fixtures analyzers/tests/fixtures`
- [ ] `go test ./...`
- [ ] `git diff --check`
```

**Commit:**

```bash
git status --short
git log --oneline --max-count=10
git commit --allow-empty -m "docs: complete analyzer engine milestone checklist" # only if a final marker commit is desired
```

---

## Suggested implementation order by dependency

1. #14 schemas and examples.
2. #15 Python workspace and schema validation SDK.
3. #54 finding ID builder.
4. #55 evidence builder.
5. #53 rule metadata registry.
6. Analyzer context/files/finding builder and CLI.
7. #56 npm lifecycle rule.
8. #57 npm network command rule.
9. #58 JS env/token rule.
10. #59 JS eval/decode rule.
11. #61 PyPI setup execution rule.
12. #62 Python decode-exec rule.
13. #63 webhook URL rule.
14. #60 unexpected binary rule.
15. #64 high entropy blob rule.
16. Cross-rule integration fixtures.
17. #16 Go contract validation, executor, and worker.
18. #18 persistence and findings API.
19. #86 fixture safety linter.
20. #87 network-off mode.
21. CI gates and docs finalization.

---

## Risk notes

- If Go database infrastructure is not implemented yet, keep findings store tests behind `TALLOW_TEST_DATABASE_URL` and still implement SQL/migration/query files so the persistence contract is ready.
- If event bus infrastructure is not implemented yet, make analyzer worker depend on small interfaces and use fakes in tests; do not block Python analyzer work on NATS.
- If JavaScript parser dependencies create instability, prefer deterministic bounded string rules for MVP and document lower confidence behavior.
- Do not add Semgrep, YARA, or external intelligence adapters in this milestone; the rule registry should make them possible later without implementing them now.
- Do not download live malicious samples. Use tiny inert fixtures with fake secrets and deterministic byte content.
