# Release Self-Protection

Tallow must protect its own releases with the same supply-chain discipline it expects from monitored packages.

## Required release artifacts

Every release must include:
- Source tag signed or otherwise verifiable by project policy.
- Checksums file containing sha256 for all release artifacts.
- SBOM for binaries/images when build tooling supports it.
- Container image digest, not only tag.
- Changelog entry.
- Migration notes for database changes.

## Build rules

- Release builds run from clean CI, not developer laptops.
- Pin toolchain versions in CI.
- Use reproducible build flags where practical.
- Do not embed secrets in binaries, images, or source maps.
- Generate artifacts once; do not rebuild after checksums are published.

## Verification commands

Document release verification in each release note:
- Download artifact.
- Download checksum file.
- Run `sha256sum -c`.
- Verify image digest with container tooling.
- Verify SBOM/provenance if published.

## Self-monitoring

Add Tallow's own packages/images to a default optional watchlist:
- GitHub releases for the repository.
- Published container images.
- Any future language package distributions.

Self-monitoring must not be hardcoded to contact external services unless explicitly enabled by the operator.

## Release gate

Before publishing:
- Full test strategy release gate passes.
- Migrations upgrade from previous release and downgrade policy is documented.
- Security docs updated for changed boundaries.
- Public schemas are versioned and examples validate.
- UI/API/CLI contract changes are documented.

## Incident response

If a Tallow release artifact is suspected compromised:
1. Mark release as revoked in project channels.
2. Publish affected artifact hashes.
3. Publish fixed release with new version.
4. Add detection rule or self-monitoring signal if possible.
5. Preserve evidence; do not delete compromised artifacts without retaining hashes and metadata.

## Default Compose protection

Default Docker Compose services must not use `privileged: true`, host networking, or Docker socket mounts. Future releases will add a Tallow self-scan hook alongside SBOM, checksum, and signing checks.
