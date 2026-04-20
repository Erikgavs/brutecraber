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

**A blazing-fast hash cracker built with Rust — now GPU-accelerated.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Built%20with-Rust-DE4A1F?logo=rust)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.9.0-orange)](https://github.com/erikgavs/brutecraber/releases)
[![crates.io](https://img.shields.io/crates/v/brutecraber.svg)](https://crates.io/crates/brutecraber)

Crack hashes using wordlist-based dictionary attacks. Runs on GPU via OpenCL when available, with automatic fallback to a parallel CPU backend powered by `rayon`.

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Supported Hashes](#-supported-hashes) · [Contributing](#-contributing)

</div>

---

## Why BruteCraber?

- **GPU by default** — OpenCL acceleration out of the box. No flag needed.
- **Automatic fallback** — If GPU isn't available, it transparently falls back to a multithreaded CPU backend.
- **Simple** — One command. No config files. No setup.
- **Smart** — Auto-detects hash types. Just point it at a file and go.
- **Wide algorithm support** — MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512, Bcrypt, NTLM, Argon2, Scrypt, PBKDF2.

---

## Performance

BruteCraber v0.9.0 ships with two backends:

- **GPU (OpenCL)** — kernels for MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512 and NTLM. Used automatically when a GPU is detected.
- **CPU (Rayon)** — SIMD-accelerated, chunked parallel processing. Used when GPU isn't available or for algorithms that can't be parallelized on GPU (Bcrypt, Argon2, Scrypt, PBKDF2).

Run `--benchmark` to measure performance on your hardware.

---

## Features

| Feature | Description |
|---------|-------------|
| **GPU acceleration** | OpenCL kernels for MD5, SHA1, SHA256, SHA512, SHA3-*, NTLM |
| **Automatic backend** | GPU when possible, transparent fallback to CPU |
| **Force CPU** | `--cpu` flag to skip the GPU path entirely |
| **Multithreading** | Parallel CPU cracking with `rayon` |
| **Auto-detection** | No need to specify hash type |
| **Modern KDFs** | Argon2, Scrypt, PBKDF2 |
| **Hex / Base64 / Salted** | All three formats for the main hex algorithms |
| **Rules engine** | Leet speak, capitalize, append numbers (GPU + CPU) |
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

### CPU-only build (no OpenCL)

If you don't have OpenCL installed and prefer a binary that never touches the GPU stack:

```bash
cargo build --release --no-default-features
```

### GPU requirements

For GPU acceleration you need the OpenCL runtime on your system:

- **Linux**: usually provided by your GPU drivers. If missing: `sudo apt install ocl-icd-libopencl1` (Debian/Ubuntu), `sudo dnf install ocl-icd` (Fedora), `sudo pacman -S ocl-icd` (Arch).
- **Windows**: `OpenCL.dll` ships with up-to-date NVIDIA/AMD/Intel drivers.
- **macOS**: built into the system.

If OpenCL or a GPU isn't available, BruteCraber automatically falls back to the CPU backend — you'll see a yellow `[!]` notice at startup.

---

## Usage

```bash
./brutecraber -f <hashes_file> -w <wordlist> [-t <hash_type>] [--cpu]
```

### Quick start

```bash
# Auto-detect hash type, GPU if available, CPU otherwise
./brutecraber -f hashes.txt -w rockyou.txt

# Force CPU backend
./brutecraber -f hashes.txt -w rockyou.txt --cpu

# Specify hash type manually
./brutecraber -f hashes.txt -w rockyou.txt -t sha256

# Crack salted hashes
./brutecraber -f salted.txt -w rockyou.txt -t md5-salt

# Crack bcrypt hashes (CPU-only algorithm)
./brutecraber -f bcrypt_hashes.txt -w rockyou.txt -t bcrypt

# Crack Argon2 hashes
./brutecraber -f argon2.txt -w rockyou.txt -t argon2

# Enable rules engine
./brutecraber -f hashes.txt -w rockyou.txt --rules
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f` | Path to file containing hashes (one per line) | *required* |
| `-w` | Path to wordlist file | *required* |
| `-t` | Hash type (see table below) | `auto` |
| `-r` / `--rules` | Enable rule-based transformations | `false` |
| `--cpu` | Force CPU backend (skip GPU) | `false` |
| `--benchmark` | Run benchmark mode (measures H/s) | `false` |
| `-h` | Show help | — |
| `-V` | Show version | — |

### Example output

```
 [*] GPU: NVIDIA GeForce RTX 3060 | VRAM: 12288 MB | Compute Units: 28

 [*] hash cracked 5f4dcc3b5aa765d61d8327deb882cf99 -> password
 [*] hash cracked 21232f297a57a5a743894a0e4a801fc3 -> admin

 [*] cracked 2/2 hashes
```

When falling back to CPU:

```
 [!] GPU unavailable (No GPU devices found), falling back to CPU
```

---

## Supported Hashes

### Hex algorithms (GPU + CPU)

| Algorithm | Hex | Base64 | Salted |
|-----------|:---:|:------:|:------:|
| MD5 | `md5` | `md5-base64` | `md5-salt` |
| SHA1 | `sha1` | `sha1-base64` | `sha1-salt` |
| SHA256 | `sha256` | `sha256-base64` | `sha256-salt` |
| SHA512 | `sha512` | `sha512-base64` | `sha512-salt` |
| SHA3-256 | `sha3-256` | `sha3-256-base64` | `sha3-256-salt` |
| SHA3-512 | `sha3-512` | `sha3-512-base64` | `sha3-512-salt` |
| NTLM | `ntlm` | — | — |

### Password-hashing algorithms (CPU only)

| Algorithm | Type | Notes |
|-----------|------|-------|
| Bcrypt | `bcrypt` | Salt embedded in hash (`$2a$`, `$2b$`, `$2y$`) |
| Argon2 | `argon2` | Modern memory-hard KDF |
| Scrypt | `scrypt` | Used in crypto wallets |
| PBKDF2 | `pbkdf2` | Enterprise standard, WiFi WPA |

> Salted hashes use the format `salt:hash` (one per line).
> Bcrypt/Argon2/Scrypt/PBKDF2 include their own salt inside the hash string.

---

## Project Structure

```
brutecraber/
├── src/
│   ├── main.rs          # CLI, banner, backend selection
│   ├── backend.rs       # CrackingBackend trait
│   ├── cpu_backend.rs   # CPU implementation (Rayon)
│   ├── gpu_backend.rs   # GPU implementation (OpenCL)
│   ├── cracker.rs       # Core CPU cracking logic
│   ├── detector.rs      # Auto-detection by hash shape
│   ├── rules.rs         # Rule-based word transformations
│   ├── benchmark.rs     # Benchmark mode (H/s measurements)
│   ├── kernels/         # OpenCL kernels (.cl files)
│   └── hashes/
│       ├── mod.rs
│       ├── md5.rs
│       ├── sha1_hash.rs
│       ├── sha256.rs
│       ├── sha512.rs
│       ├── sha3_256.rs
│       ├── sha3_512.rs
│       ├── ntlm.rs
│       ├── bcrypt.rs
│       ├── argon2.rs
│       ├── scrypt.rs
│       └── pbkdf2.rs
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
- [x] Benchmark mode (`--benchmark`)
- [x] Rule-based transformations (leet speak, capitalize, append numbers)
- [x] SIMD optimizations & chunked parallel processing
- [x] CI/CD pipeline (cargo test, clippy, rustfmt, audit)
- [x] Argon2 support
- [x] Scrypt support
- [x] PBKDF2 support
- [x] GPU acceleration (OpenCL) with automatic CPU fallback
- [ ] Output results to file (`-o`)
- [ ] Potfile (remember cracked hashes between runs)
- [ ] Salted variants on GPU (`md5-salt`, `sha256-salt`, …)
- [ ] Mask attack (`?l?l?d?d` style)
- [ ] Multi-GPU support
- [ ] Expanded hash auto-detection (crypt formats, MySQL, phpass, …)
- [ ] SIMD multi-buffer hashing on CPU (hash 4–8 passwords simultaneously)

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
