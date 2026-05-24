# Built-in Rules and Future Adapters

Tallow starts with deterministic built-in rules. Each rule has a stable ID, evidence references, severity suggestion, confidence, and tests.

## Initial rule families

- `artifact.hash.registry_mismatch`
- `artifact.hash.observed_changed`
- `npm.lifecycle.postinstall_added`
- `npm.lifecycle.install_script_changed`
- `js.execution.child_process_added`
- `js.obfuscation.eval_decode_chain`
- `js.secrets.env_token_access`
- `py.setup.subprocess_execution`
- `py.obfuscation.decode_exec_chain`
- `network.webhook_url_added`
- `artifact.binary_added`
- `artifact.high_entropy_blob_added`

## Future adapter types

- Semgrep adapter for source pattern rules.
- YARA adapter for string/binary signatures.
- OSV/OpenSSF intelligence adapter.
- Community signed rule packs.
- Custom local rule directories.

All adapters normalize results into Tallow findings.
