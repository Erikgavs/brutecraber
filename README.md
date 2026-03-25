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

- 🔓 MD5, SHA1 and SHA256 hash cracking via wordlist
- 🔑 Base64 support for MD5, SHA1 and SHA256
- 🎨 Colored terminal output
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
./brutecraber -f <hashes_file> -w <wordlist> -t <hash_type>
```

### 📝 Examples

```bash
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
```

### 🔧 Options

| Flag | Description |
|------|-------------|
| `-f` | Path to file containing hashes (one per line) |
| `-w` | Path to wordlist file |
| `-t` | Hash type: `md5`, `md5-base64`, `sha1`, `sha1-base64`, `sha256`, `sha256-base64` |
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

## ⚠️ Disclaimer

This tool is intended for **ethical hacking and educational purposes only**. Unauthorized use against systems without prior consent is illegal. Use at your own risk.

## 👤 Author

**erikgavs**
