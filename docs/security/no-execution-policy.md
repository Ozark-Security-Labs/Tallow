# No-Execution Policy

Tallow's default analysis mode is static. Analyzer workers must not execute package code, install packages, run lifecycle hooks, import arbitrary modules from analyzed artifacts, or invoke package manager commands that execute project/package scripts.

## Allowed by default

- Read registry metadata.
- Download artifacts.
- Validate registry-provided hashes against locally computed hashes.
- Safely unpack archives with bounded extraction.
- Read files as bytes/text under configured limits.
- Parse manifests, lockfiles, and source files.
- Build ASTs using parser libraries that do not execute code.
- Compute hashes, entropy, file type summaries, and deterministic diffs.

## Not allowed by default

- `npm install`, `pip install`, `python setup.py`, `go test`, `cargo build`, or equivalent package execution against untrusted artifacts.
- Importing Python modules from analyzed packages.
- Running JavaScript, shell scripts, build scripts, postinstall hooks, or native binaries from analyzed artifacts.
- Giving analyzer containers host credentials, package registry tokens, SSH keys, Docker socket access, or broad host mounts.
- Sending raw artifact contents to LLM providers unless a future explicitly enabled redaction/allowlist policy permits it.

## Future dynamic analysis

Sandboxed dynamic analysis may be added later as a separate capability. It must have separate configuration, separate docs, explicit operator opt-in, no host secrets, constrained egress, and auditable telemetry. Static analysis must remain usable without dynamic execution.
