# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Evidence is now source-explicit.** `EvidenceKind` is `Body` / `Response` /
  `Header { name }`, each with an optional regex, replacing the old
  `BodyRef` / `ResponseRef` / source-less `Regex` variants. A header value can
  now be used as proof directly (`evidence p.header "X-Powered-By"`); previously
  a bare `evidence p regex '…'` silently ran against the body and mis-fired when
  the proof lived in a header. The bytecode evidence-pool encoding changed
  accordingly (the magic/VERSION are unchanged — the registry is republished in
  lockstep so no old-format evidence bytecode survives).

## [1.0.0] - 2026-06-16

Initial 1.0 release.
