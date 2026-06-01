# Changelog

All notable changes to `ruso-runtime` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and the project
aims to follow [Semantic Versioning](https://semver.org/).

## [0.1.0-beta.1] - 2026-05-30

First public beta. Bytecode stays at wire format **v1** (evolved in place
during the pre-1.0 series; it will be frozen at the first stable release).

### Added
- Regex matcher on HTTP **header** values (`probe.header "X" regex '…'`),
  alongside the existing body/response regex.
- Script metadata `family`, `version`, and `tags` are carried through the
  spec, bytecode, and disassembler.

### Changed
- Metadata `mitigation` is now a single `Option<String>` (was a list).

### Fixed
- UDP and wire-DNS probes are no longer wrongly skipped: the pre-run port
  check is a TCP connect and only applies to TCP probes now.
- The pre-run port check resolves `{{scan_host}}` from the target the same
  way the send path does, so socket probes aren't skipped against the literal
  placeholder.
- Avoid an eager payload clone in TCP/UDP probe dispatch (`or` → `or_else`).

### Security
- Decode-time validation of every instruction operand index against its pool.
  A corrupt or malicious `.bc` can no longer panic the executor with an
  out-of-bounds index; it surfaces as a clean `Corrupt` error.

[0.1.0-beta.1]: https://github.com/Hopeless-Labs/ruso-runtime/releases/tag/v0.1.0-beta.1
