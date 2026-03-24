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

- 🔓 MD5 hash cracking via wordlist
- 🔑 MD5-Base64 support (decodes Base64-encoded MD5 hashes before cracking)
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
```

### 🔧 Options

| Flag | Description |
|------|-------------|
| `-f` | Path to file containing hashes (one per line) |
| `-w` | Path to wordlist file |
| `-t` | Hash type: `md5`, `md5-base64` |
| `-h` | Show help |

## 📄 Supported hash types

| Type | Description |
|------|-------------|
| `md5` | Standard MD5 hashes in hexadecimal |
| `md5-base64` | MD5 hashes encoded in Base64 |

## 📄 Hash file format

One hash per line:

```
900150983cd24fb0d6963f7d28e17f72
e99a18c428cb38d5f260853678922e03
827ccb0eea8a706c4c34a16891f84e7b
```

## ⚠️ Disclaimer

This tool is intended for **ethical hacking and educational purposes only**. Unauthorized use against systems without prior consent is illegal. Use at your own risk.

## 👤 Author

**erikgavs**
