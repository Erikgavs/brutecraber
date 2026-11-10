# Usage
> This documentation applies to brutecraber v0.10.0

> This project is under active development

## Running the tool

After installation, you can run the tool using the binary

```bash
./brutecraber
```

By default, the tool will display some help for the user

```bash
./brutecraber --help
```

## Command line options

| Flag | Description |
|------|-------------|
| `-f` | Path to the file containing hashes to crack |
| `-w` | Path to the wordlist file |
| `-t` | Hash type (default: `auto`) |
| `-r` / `--rules` | Enable rule-based transformations |
| `--cpu` | Force CPU backend |
| `--benchmark` | Run CPU/GPU benchmarks |
| `--detect-hash <FILE>` | Detect hash types in a hash file |
| `-j <N>` | Set the number of worker threads |
| `-V` | Show current version |

## Supported hash types

| Type | Flag value |
|------|------------|
| MD5 | `md5` |
| MD5 Base64 | `md5-base64` |
| MD5 Salted | `md5-salt` |
| MD5 Salted (password + salt) | `md5-salt-suffix` |
| SHA1 | `sha1` |
| SHA1 Base64 | `sha1-base64` |
| SHA1 Salted | `sha1-salt` |
| SHA1 Salted (password + salt) | `sha1-salt-suffix` |
| SHA256 | `sha256` |
| SHA256 Base64 | `sha256-base64` |
| SHA256 Salted | `sha256-salt` |
| SHA256 Salted (password + salt) | `sha256-salt-suffix` |
| SHA512 | `sha512` |
| SHA512 Base64 | `sha512-base64` |
| SHA512 Salted | `sha512-salt` |
| SHA512 Salted (password + salt) | `sha512-salt-suffix` |
| SHA3-256 | `sha3-256` |
| SHA3-256 Base64 | `sha3-256-base64` |
| SHA3-256 Salted | `sha3-256-salt` |
| SHA3-256 Salted (password + salt) | `sha3-256-salt-suffix` |
| SHA3-512 | `sha3-512` |
| SHA3-512 Base64 | `sha3-512-base64` |
| SHA3-512 Salted | `sha3-512-salt` |
| SHA3-512 Salted (password + salt) | `sha3-512-salt-suffix` |
| Bcrypt | `bcrypt` |
| NTLM | `ntlm` |
| Argon2 | `argon2` |
| Scrypt | `scrypt` |
| PBKDF2-SHA256 PHC | `pbkdf2` |

## Rules

When `--rules` is enabled, each word in the wordlist generates multiple variants:

| Rule | Example (`password`) |
|------|----------------------|
| Original | `password` |
| Capitalize | `Password` |
| Uppercase | `PASSWORD` |
| Reverse | `drowssap` |
| Append number | `password1`, `password123` |
| Append symbol | `password!`, `password@` |
| Append year | `password2026`, `password2025`... |
| Leet speak | `p@$$w0rd` |

This increases cracking chances without needing a bigger wordlist.

## Hash file format

One hash per line. Blank lines and full-line comments beginning with `#` are ignored. Wordlists must be valid UTF-8; invalid byte sequences are rejected rather than silently replaced.

```
5f4dcc3b5aa765d61d8327deb882cf99
e10adc3949ba59abbe56e057f20f883e
```

For `*-salt` hashes, use `salt:hash` format; Brutecraber computes `hash(salt + candidate)`:

```
abc123:5f4dcc3b5aa765d61d8327deb882cf99
mysalt:e10adc3949ba59abbe56e057f20f883e
```

For `*-salt-suffix`, use `hash:salt`; Brutecraber computes `hash(candidate + salt)`:

```
9af87eabc21c318d6839aea39d5156bb:x7k2
```

Username-prefixed raw hashes (`username:hash`) are accepted when `-t` explicitly selects the hash type. Auto-detection rejects colon-delimited records because username/hash and salted formats are ambiguous. Base64 modes accept padded and unpadded standard Base64, but also require an explicit `-t` type. Invalid and duplicate hash records are reported and excluded; the cracked total counts unique target hashes.

Hashes with 32 hex characters are ambiguous between MD5 and NTLM; auto mode tries both. Hashes with 64 or 128 characters are tried as SHA-2/SHA-3 pairs.

Raw SHA-512 (`sha512`) is not Unix SHA-512-crypt (`$6$`); SHA-512-crypt and other `crypt` formats are not supported.

GPU kernels are single-block implementations. Maximum candidate lengths are 55 bytes for MD5/SHA-1/SHA-256, 111 for SHA-512, 135 for SHA3-256, 71 for SHA3-512 and 27 ASCII characters for NTLM. Overlong candidates, non-ASCII NTLM candidates and GPU execution failures fall back to CPU.
