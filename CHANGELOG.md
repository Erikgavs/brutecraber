# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.7.0] - 2026-04-02

### Added
- SHA3-256 hash cracking support (hex, base64, salted)
- Rule-based transformations connected to cracker (`--rules` / `-r` flag)
- Dual auto-detection for SHA256/SHA3-256 hashes
- Hash type validation before cracking loop
- Documentation: `docs/usage.md`, `docs/examples.md`

### Fixed
- `Cargo.toml` version synced correctly
- `Cargo.toml` edition corrected from "2024" to "2021"
- Help text now lists bcrypt and ntlm as supported types

### Contributors
- @Deepak8858 — SHA3-256 support (#29)
- @aniketchavan2211 — Release workflow (#30)
- @piny4man — MD5 crate migration to RustCrypto (#33)

## [0.6.0] - 2026-03-28

### Added
- Bcrypt hash cracking support
- NTLM hash cracking support (Windows hashes)
- Progress bar with `indicatif`
- UTF-8 lossy handling for wordlists (no more crashes with rockyou.txt)
- Rule-based transformation module (leet speak, capitalize, append numbers, etc.)
- CONTRIBUTING.md for open-source contributors
- Improved `--help` with flag descriptions

## [0.5.0] - 2026-03-26

### Added
- Salted hash support for MD5, SHA1, SHA256 and SHA512
- New hash types: `md5-salt`, `sha1-salt`, `sha256-salt`, `sha512-salt`
- `crack_with_salt()` function in each hash module
- Test files for salted hashes
- Multithreaded cracking with `rayon` (parallel wordlist processing)
- `--version` (`-V`) flag
- Help descriptions for all CLI flags
- Supported hashes and modes info in banner

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
