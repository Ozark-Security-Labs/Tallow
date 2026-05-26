# Built-in Rules and Future Adapters

Tallow starts with deterministic built-in rules. Each rule has a stable ID, evidence references, severity suggestion, confidence, and tests.

## Initial rule families

- `npm.lifecycle.install_script`: flags npm install lifecycle script keys.
- `npm.lifecycle.network_command`: flags network-capable commands in npm lifecycle scripts.
- `js.secrets.env_token_access`: flags token-like `process.env` access and credential path reads.
- `js.obfuscation.eval_decode_chain`: flags JavaScript decode-to-execution chains.
- `pypi.setup.exec_call`: flags execution sinks in Python packaging setup files.
- `py.obfuscation.decode_exec_chain`: flags Python decode/decompress-to-execution chains.
- `network.webhook_url`: flags webhook-like exfiltration URLs in executable package files.
- `artifact.binary.unexpected`: flags unexpected ELF/PE/Mach-O native binaries.
- `artifact.entropy.high_blob`: flags new high-entropy text blobs without storing the blob.

## Limitations

- Built-in rules are static and heuristic; they do not execute package code or prove exploitability.
- JavaScript checks use bounded source scanning instead of a full JavaScript parser in the MVP.
- High-entropy findings report path, line, entropy, length, and a hash, not raw blob contents.
- Documentation/prose files are skipped for webhook findings by default to reduce false positives.
- Binary packages must be explicitly allowed with `allow_binary_packages` or `allowed_binary_paths`.

## Future adapter types

- Semgrep adapter for source pattern rules.
- YARA adapter for string/binary signatures.
- OSV/OpenSSF intelligence adapter.
- Community signed rule packs.
- Custom local rule directories.

All adapters normalize results into Tallow findings.
