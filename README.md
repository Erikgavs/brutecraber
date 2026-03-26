```
 ___.                 __                            ___.
 \_ |_________ __ ___/  |_  ____   ________________ \_ |__   ___________
  | __ \_  __ \  |  \   __\/ __ \_/ ___\_  __ \__  \ | __ \_/ __ \_  __ \
  | \_\ \  | \/  |  /|  | \  ___/\  \___|  | \// __ \| \_\ \  ___/|  | \/
  |___  /__|  |____/ |__|  \___  >\___  >__|  (____  /___  /\___  >__|
      \/                       \/     \/           \/    \/     \/
```

# 🦀 BruteCraber

A fast hash cracker using wordlist-based dictionary attacks. Built with Rust.

## ✨ Features

- 🔓 MD5, SHA1, SHA256 and SHA512 hash cracking via wordlist
- 🔑 Base64 support for all hash types
- 🧂 Salted hash support (format: `salt:hash`)
- 🔍 Auto-detection of hash type (no need to specify `-t`)
- 🎨 Colored terminal output
- 📁 Modular architecture (separate modules per hash type)
- ⚡ Clean CLI interface with `-f`, `-w` and `-t` flags

## 📦 Installation

```bash
git clone https://github.com/erikgavs/brutecraber.git
cd brutecraber
cargo build --release
```

The binary will be at `./target/release/brutecraber`.

## 🚀 Usage

```bash
./brutecraber -f <hashes_file> -w <wordlist> [-t <hash_type>]
```

### 📝 Examples

```bash
# Auto-detect hash type
./brutecraber -f hashes.txt -w wordlist.txt

# Crack MD5 hashes
./brutecraber -f hashes.txt -w wordlist.txt -t md5

# Crack MD5 hashes encoded in Base64
./brutecraber -f hashes_base64.txt -w wordlist.txt -t md5-base64

# Crack SHA1 hashes
./brutecraber -f hashes.txt -w wordlist.txt -t sha1

# Crack SHA1 hashes encoded in Base64
./brutecraber -f hashes_base64.txt -w wordlist.txt -t sha1-base64

# Crack SHA256 hashes
./brutecraber -f hashes.txt -w wordlist.txt -t sha256

# Crack SHA256 hashes encoded in Base64
./brutecraber -f hashes_base64.txt -w wordlist.txt -t sha256-base64

# Crack SHA512 hashes
./brutecraber -f hashes.txt -w wordlist.txt -t sha512

# Crack SHA512 hashes encoded in Base64
./brutecraber -f hashes_base64.txt -w wordlist.txt -t sha512-base64

# Crack MD5 salted hashes (format: salt:hash)
./brutecraber -f salted_hashes.txt -w wordlist.txt -t md5-salt

# Crack SHA1 salted hashes
./brutecraber -f salted_hashes.txt -w wordlist.txt -t sha1-salt

# Crack SHA256 salted hashes
./brutecraber -f salted_hashes.txt -w wordlist.txt -t sha256-salt

# Crack SHA512 salted hashes
./brutecraber -f salted_hashes.txt -w wordlist.txt -t sha512-salt
```

### 🔧 Options

| Flag | Description |
|------|-------------|
| `-f` | Path to file containing hashes (one per line) |
| `-w` | Path to wordlist file |
| `-t` | Hash type (optional, auto-detected if not specified): `md5`, `md5-base64`, `md5-salt`, `sha1`, `sha1-base64`, `sha1-salt`, `sha256`, `sha256-base64`, `sha256-salt`, `sha512`, `sha512-base64`, `sha512-salt` |
| `-h` | Show help |

## 📄 Supported hash types

| Type | Description |
|------|-------------|
| `md5` | Standard MD5 hashes in hexadecimal |
| `md5-base64` | MD5 hashes encoded in Base64 |
| `sha1` | Standard SHA1 hashes in hexadecimal |
| `sha1-base64` | SHA1 hashes encoded in Base64 |
| `sha256` | Standard SHA256 hashes in hexadecimal |
| `sha256-base64` | SHA256 hashes encoded in Base64 |
| `sha512` | Standard SHA512 hashes in hexadecimal |
| `sha512-base64` | SHA512 hashes encoded in Base64 |
| `md5-salt` | MD5 hashes with salt (format: `salt:hash`) |
| `sha1-salt` | SHA1 hashes with salt (format: `salt:hash`) |
| `sha256-salt` | SHA256 hashes with salt (format: `salt:hash`) |
| `sha512-salt` | SHA512 hashes with salt (format: `salt:hash`) |

## ⚠️ Disclaimer

This tool is intended for **ethical hacking and educational purposes only**. Unauthorized use against systems without prior consent is illegal. Use at your own risk.

## 👤 Author

**erikgavs**
