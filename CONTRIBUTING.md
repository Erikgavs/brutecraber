# Contributing to BruteCraber

Thanks for your interest in contributing! This guide will help you get started.

## Getting Started

1. Fork the repo
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/brutecraber.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run checks: `cargo test && cargo clippy`
6. Push and open a Pull Request

## Test suites

The regular Scrypt tests use low-cost PHC fixtures (`ln=10`) so `cargo test` can check verification quickly. These fixtures are for tests only and are not suitable for production password storage.

One round-trip test uses the default, slower Scrypt cost and is ignored by default. Run it explicitly with:

```bash
cargo test --locked hashes::scrypt::tests::slow_default_cost_scrypt_round_trip -- --ignored --exact
```

This slow check can take a minute or more depending on the machine.

## Project Structure

```
src/
├── main.rs          # CLI, banner, entry point
├── cracker.rs       # Core cracking logic (multithreaded)
├── detector.rs      # Auto-detection by hash length
├── rules.rs         # Word transformation rules
└── hashes/
    ├── mod.rs       # Module exports
    ├── md5.rs       # MD5 hashing
    ├── sha1_hash.rs # SHA1 hashing
    ├── sha256.rs    # SHA256 hashing
    ├── sha512.rs    # SHA512 hashing
    └── bcrypt.rs    # Bcrypt verification
```

## What Can I Contribute?

Everything is open for contributions:

- New hash types (NTLM, SHA3, scrypt, Argon2, etc.)
- Core improvements (cracker, detector, CLI)
- Performance optimizations
- Bug fixes
- Documentation

## Adding a New Hash Type

1. Create `src/hashes/your_hash.rs` with a `crack(word: &str) -> String` function
2. Add `pub mod your_hash;` in `src/hashes/mod.rs`
3. Add a new match arm in `src/cracker.rs`
4. Add tests with `#[cfg(test)]`
5. Create test files in `tests/hashes/your_hash/`
6. Update `README.md` and `CHANGELOG.md`

Look at `md5.rs` as a reference for the pattern.

## Requirements

Before submitting a PR:

- [ ] `cargo test` — All tests must pass
- [ ] `cargo clippy` — No warnings allowed
- [ ] `cargo fmt` — Code must be formatted

## Commit & PR Convention

Use prefixes for commits and PR titles:

| Prefix | Usage |
|--------|-------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation changes |
| `refactor:` | Code refactoring |
| `test:` | Adding or updating tests |

Example: `feat: add NTLM hash support`

## PR Guidelines

- One feature per PR — keep it focused
- Write in English (code, comments, PR description)
- Include tests for new functionality
- Update docs if your change affects usage

## Reporting Bugs

Open an issue with:

- What you expected to happen
- What actually happened
- Steps to reproduce
- OS and Rust version (`rustc --version`)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
