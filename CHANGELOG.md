# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- local file loading support for OSV vulnerability data (`local` feature)
- optional data retrieval for OSV dataset from GCS (`data` feature)
- Ubuntu Pro FIPS ecosystem support
- derive Clone on most public types
- support for Reference and Severity without type field

### Changed

- update OSV schema from 1.6.7 to 1.7.4
- ubuntu ecosystem parsing refactored to use regex

### Fixed

- fix openSUSE ecosystem case
- fix missing `:for:` when serializing Ubuntu metadata
- fix typos in CreditType comments

## [0.2.1](https://github.com/gcmurphy/osv/compare/v0.2.0...v0.2.1) - 2025-02-20

### Added

- add fuzz testing
- add rh, suse, and chainguard ecosystems
- remove invalid dev dependencies
- the published field is optional
- add gh action for semgrep, devskim, audit and fuzzing
- add scorecard badge
- enable publishing of scorecard results
- update default permissions for all workflows

[Unreleased]: https://github.com/gcmurphy/osv/compare/v0.2.2...HEAD
