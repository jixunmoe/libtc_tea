# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2022-12-29

### Changed

- Reduced memory allocation during decryption.
- Reduced memory footprint while encrypt and decrypt data.
- Dropped requirement of C++20 to C++17.
- **BREAKING** API changed - raw API fallback to pointers, while vector API takes a vector instead of span.

## [0.1.0] - 2023-02-01

### Added

- Source import from [libparakeet].
- Support both CBC & EBC mode for `tc_tea`.

[libparakeet]: https://github.com/parakeet-rs/libparakeet
[0.1.0]: https://github.com/jixunmoe/libtc_tea/commits/v0.1.0
[0.1.1]: https://github.com/jixunmoe/libtc_tea/compare/v0.1.0...v0.1.1
