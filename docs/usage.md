# Usage
> This documentation applies to brutecraber v0.7.0

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
| SHA1 | `sha1` |
| SHA1 Base64 | `sha1-base64` |
| SHA1 Salted | `sha1-salt` |
| SHA256 | `sha256` |
| SHA256 Base64 | `sha256-base64` |
| SHA256 Salted | `sha256-salt` |
| SHA512 | `sha512` |
| SHA512 Base64 | `sha512-base64` |
| SHA512 Salted | `sha512-salt` |
| Bcrypt | `bcrypt` |
| NTLM | `ntlm` |

## Examples

Basic usage with auto-detection:

```bash
./brutecraber -f hashes.txt -w wordlist.txt
```

Specify hash type:

```bash
./brutecraber -f hashes.txt -w rockyou.txt -t sha256
```

With rule-based transformations:

```bash
./brutecraber -f hashes.txt -w rockyou.txt -t md5 --rules
```

Salted hashes (file format: `salt:hash` per line):

```bash
./brutecraber -f salted.txt -w rockyou.txt -t md5-salt
```

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

For salted hashes, use `salt:hash` format:

```
abc123:5f4dcc3b5aa765d61d8327deb882cf99
mysalt:e10adc3949ba59abbe56e057f20f883e
```
