# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.9.0] - 2026-04-20

### Added
- **GPU acceleration via OpenCL** — kernels for MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512 and NTLM
- **Automatic backend selection** — GPU is used by default when available; transparent fallback to CPU if OpenCL is missing, the device fails to initialize, or the hash type is not GPU-supported
- `--cpu` flag to force the CPU backend
- **Argon2** hash cracking support
- **Scrypt** hash cracking support
- **PBKDF2** hash cracking support
- `CrackingBackend` trait and `CpuBackend` / `GpuBackend` abstraction
- GPU-side rules support and dual-mode hash types
- GPU test suite with CPU-vs-GPU correctness checks
- Auto-detector now recognizes Argon2, Bcrypt, Scrypt and PBKDF2
- CI workflow for PRs (`ci.yml`): fmt, clippy and tests on every pull request
- Release pipeline hardening (`rust.yml`): `cargo audit`, fmt, clippy and tests before packaging

### Changed
- **License changed from GPL-3.0 to MIT**
- `gpu` feature is now enabled by default; CPU-only builds available with `--no-default-features`
- Banner and help text refreshed; backend selection messages unified
- Benchmark path simplified — uses the active feature set directly

### Contributors
- @piny4man — initial GPU experiment and OpenCL backend (#53)
- @aniketchavan2211 — release pipeline hardening with `cargo audit` (#57)

## [0.8.1] - 2026-04-08

### Performance
- Chunked parallel processing with `par_chunks(64)` for reduced thread synchronization overhead (+20-60% multi-thread performance)
- SIMD-accelerated hex decoding via `faster-hex` crate
- Enabled ASM features for `md-5`, `sha1`, `sha2` crates (benefits CPUs with SHA-NI support)

### Changed
- Updated to Rust Edition 2024

### Benchmark Improvements (4-core Intel)
| Hash | v0.8.0 | v0.8.1 | Improvement |
|------|--------|--------|-------------|
| MD5 | 7.58 MH/s | 8.05 MH/s | +6% |
| SHA256 | 2.41 MH/s | 2.94 MH/s | +22% |
| SHA512 | 1.90 MH/s | 2.28 MH/s | +20% |
| SHA3-256 | 1.21 MH/s | 1.78 MH/s | +47% |
| SHA3-512 | 1.16 MH/s | 1.85 MH/s | +59% |

## [0.8.0] - 2026-04-07

### Added
- SHA3-512 hash cracking support (hex, base64, salted)
- Dual auto-detection for SHA512/SHA3-512 hashes (128-char length)
- Benchmark mode (`--benchmark`) — measures hashes per second (H/s) in single-thread and multi-thread (Rayon)
- CPU info output during benchmark (Rayon threads, available cores)
- Test files for SHA3-512 in `tests/hashes/sha3-512/`

### Contributors
- @aniketchavan2211 — Benchmark mode (#42), CI/CD workflow improvements (#38)

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
