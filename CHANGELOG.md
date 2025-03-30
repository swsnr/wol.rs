# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

To make a release run [cargo release](https://github.com/crate-ci/cargo-release),
push the release commit, wait for Github actions to finish, then push the release tag.
Github workflows then take care of building release artifacts and publishing the release.

## [Unreleased]

## [0.3.0] – 2025-03-30

### Added
- Add `wol::file` module to read "wakeup files", i.e. files containing hosts to wake up.
- Implement the `--file` option.

### Changed
- Use a dedicated `SecureOn` type for SecureOn tokens.

## [0.2.3] – 2025-03-27

### Added
- Build Windows and Linux binaries for releases.

## [0.2.2] – 2025-03-26

### Added
- Add manpage and shell completions

## [0.2.1] – 2025-03-25

### Added
- Publish to crates.io

## [0.2.0] – 2025-03-25

Preliminary release of command line utility and crate.

[Unreleased]: https://github.com/swsnr/wol.rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/swsnr/wol.rs/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/swsnr/wol.rs/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/swsnr/wol.rs/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/swsnr/wol.rs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/swsnr/wol.rs/releases/tag/v0.2.0
