# Synthetic prompt-injection fixtures

All files in this directory are safe, inert, synthetic Tallow-owned fixtures. They are not copied from live malicious samples, external corpora, package artifacts, or proof-of-concept tooling. Treat their content as hostile untrusted evidence in tests.

The manifest uses stable Tallow labels aligned with OWASP ASI-01 prompt-injection concepts for metadata only. No external taxonomy package is required.

Coverage includes direct, indirect, metadata/API, fake secret exfiltration, severity override, tool execution, finding hiding, schema breakout, memory-persistent/write-path, and multi-turn resurfacing vectors. Expected behavior is that hostile text remains quoted or summarized as untrusted evidence and never becomes trusted instructions, policy, canonical severity, tool access, or output schema.
