# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.4.0] - 2026-03-25

### Added
- SHA256 hash cracking via wordlist
- SHA256-Base64 support
- Test files for SHA256 and SHA256-Base64

### Changed
- Refactored hash type selection from if/else to match
- Updated test files with more realistic passwords

## [0.3.0] - 2026-03-25

### Added
- SHA1 hash cracking via wordlist
- SHA1-Base64 support
- Test files for SHA1 and SHA1-Base64

## [0.2.0] - 2026-03-25

### Added
- MD5-Base64 support (decodes Base64-encoded MD5 hashes before cracking)
- `-t` flag to select hash type
- Colored banner with Rust orange (#DE4A1F)
- Disclaimer notice on startup

## [0.1.0] - 2026-03-24

### Added
- MD5 hash cracking via wordlist
- CLI interface with `-f` and `-w` flags
- Colored output
- Banner with author info
