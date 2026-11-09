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
| PBKDF2 | `pbkdf2` |

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

One hash per line:

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

Username-prefixed raw hashes (`username:hash`) are accepted when `-t` explicitly selects the hash type. Auto-detection rejects colon-delimited records because username/hash and salted formats are ambiguous. Base64 modes accept padded and unpadded standard Base64, but also require an explicit `-t` type.
