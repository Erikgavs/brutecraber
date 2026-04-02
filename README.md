```
 ___.                 __                            ___.
 \_ |_________ __ ___/  |_  ____   ________________ \_ |__   ___________
  | __ \_  __ \  |  \   __\/ __ \_/ ___\_  __ \__  \ | __ \_/ __ \_  __ \
  | \_\ \  | \/  |  /|  | \  ___/\  \___|  | \// __ \| \_\ \  ___/|  | \/
  |___  /__|  |____/ |__|  \___  >\___  >__|  (____  /___  /\___  >__|
      \/                       \/     \/           \/    \/     \/
```

<div align="center">

# BruteCraber

**A blazing-fast, multithreaded hash cracker built with Rust.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/Built%20with-Rust-DE4A1F?logo=rust)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.7.1-orange)](https://github.com/erikgavs/brutecraber/releases)
[![crates.io](https://img.shields.io/crates/v/brutecraber.svg)](https://crates.io/crates/brutecraber)

Crack hashes using wordlist-based dictionary attacks. Powered by `rayon` for parallel processing across all CPU cores.

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Supported Hashes](#-supported-hashes) · [Contributing](#-contributing)

</div>

---

## Why BruteCraber?

- **Fast** — Multithreaded by default. Uses all your CPU cores out of the box.
- **Simple** — One command. No config files. No setup.
- **Smart** — Auto-detects hash types. Just point it at a file and go.
- **17 modes** — Hex, Base64, Salted, Bcrypt, NTLM, and SHA3-256 support.

---

## Features

| Feature | Description |
|---------|-------------|
| **Multithreading** | Parallel cracking with `rayon` — scales with your CPU |
| **Auto-detection** | No need to specify hash type, BruteCraber figures it out |
| **Hex hashes** | MD5, SHA1, SHA256, SHA512 |
| **Bcrypt** | Bcrypt hash verification (`$2b$`, `$2y$`) |
| **Base64 hashes** | Base64-encoded versions of all hash types |
| **Salted hashes** | Support for `salt:hash` format |
| **Colored output** | Clear, readable terminal output |

---

## Installation

### From crates.io (recommended)

```bash
cargo install brutecraber
```

### From source

```bash
git clone https://github.com/erikgavs/brutecraber.git
cd brutecraber
cargo build --release
```

The binary will be at `./target/release/brutecraber`.

---

## Usage

```bash
./brutecraber -f <hashes_file> -w <wordlist> [-t <hash_type>]
```

### Quick start

```bash
# Auto-detect hash type
./brutecraber -f hashes.txt -w rockyou.txt

# Specify hash type manually
./brutecraber -f hashes.txt -w rockyou.txt -t sha256

# Crack salted hashes
./brutecraber -f salted.txt -w rockyou.txt -t md5-salt

# Crack bcrypt hashes
./brutecraber -f bcrypt_hashes.txt -w rockyou.txt -t bcrypt

# Crack NTLM hashes (Windows)
./brutecraber -f ntlm_hashes.txt -w rockyou.txt -t ntlm
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f` | Path to file containing hashes (one per line) | *required* |
| `-w` | Path to wordlist file | *required* |
| `-t` | Hash type (see table below) | `auto` |
| `-r` / `--rules` | Enable rule-based transformations | `false` |
| `-h` | Show help | — |
| `-V` | Show version | — |

### Example output

```
 [*] hash cracked 5f4dcc3b5aa765d61d8327deb882cf99 -> password
 [*] hash cracked 21232f297a57a5a743894a0e4a801fc3 -> admin
 [*] hash cracked [salt:x7k2] 86f75bc83edcd705c834c436f6b64fdc -> password

 [*] cracked 3/3 hashes
```

---

## Supported Hashes

| Algorithm | Hex | Base64 | Salted |
|-----------|:---:|:------:|:------:|
| MD5 | `md5` | `md5-base64` | `md5-salt` |
| SHA1 | `sha1` | `sha1-base64` | `sha1-salt` |
| SHA256 | `sha256` | `sha256-base64` | `sha256-salt` |
| SHA512 | `sha512` | `sha512-base64` | `sha512-salt` |
| SHA3-256 | `sha3-256` | `sha3-256-base64` | `sha3-256-salt` |
| Bcrypt | `bcrypt` | — | — |
| NTLM | `ntlm` | — | — |

> Salted hashes use the format `salt:hash` (one per line).
> Bcrypt hashes include their own salt internally (`$2y$10$...`).

---

## Project Structure

```
brutecraber/
├── src/
│   ├── main.rs          # CLI, banner, entry point
│   ├── cracker.rs       # Core cracking logic (multithreaded)
│   ├── detector.rs      # Auto-detection by hash length
│   ├── rules.rs         # Rule-based word transformations
│   └── hashes/
│       ├── mod.rs       # Module exports
│       ├── md5.rs       # MD5 hashing
│       ├── sha1_hash.rs # SHA1 hashing
│       ├── sha256.rs    # SHA256 hashing
│       ├── sha512.rs    # SHA512 hashing
│       ├── sha3_256.rs  # SHA3-256 hashing
│       ├── bcrypt.rs    # Bcrypt verification
│       └── ntlm.rs     # NTLM hashing (Windows)
├── tests/               # Test hashes and wordlists
├── Cargo.toml
├── CHANGELOG.md
└── LICENSE
```

---

## Roadmap

- [x] Progress bar with `indicatif`
- [x] Bcrypt support
- [x] NTLM hash support
- [ ] Output results to file (`-o`)
- [ ] Benchmark mode (`--benchmark`)
- [ ] Statistics (time, hashes/sec)
- [x] Rule-based transformations (leet speak, capitalize, append numbers)

---

## Contributing

Contributions are welcome! Check out the [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started.

---

## Disclaimer

> This tool is intended for **ethical hacking, penetration testing, and educational purposes only**. You are solely responsible for your actions. Using this tool against targets without prior consent is a violation of applicable laws. Use at your own risk.

---

<div align="center">

Made with Rust by **[erikgavs](https://github.com/erikgavs)**

If you find this useful, consider giving it a star!

</div>
