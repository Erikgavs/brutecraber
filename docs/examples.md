# Examples
> This documentation applies to brutecraber v0.10.0

> This project is under active development

## Basic usage with auto-detection

The tool detects the hash type from the input records. It rejects mixed or colon-delimited records in auto mode rather than guessing or partially cracking them. A 32-character hex digest is ambiguous between MD5 and NTLM, so auto mode tries both. 64-character and 128-character digests are also tried as SHA/SHA3 pairs.

```bash
./brutecraber -f hashes.txt -w wordlist.txt
```

## Specify hash type

If auto-detection fails or you want to be explicit, use the `-t` flag.

```bash
./brutecraber -f hashes.txt -w rockyou.txt -t sha256
```

## With rule-based transformations

Enable `--rules` to generate multiple variants of each word (capitalize, leet speak, append numbers, etc.)

```bash
./brutecraber -f hashes.txt -w rockyou.txt -t md5 --rules
```

## Salted hashes

For `-salt` types, use `salt:hash`; the candidate is appended after the salt before hashing.

```bash
./brutecraber -f salted.txt -w rockyou.txt -t md5-salt
```

For `-salt-suffix` types, use `hash:salt`; the salt is appended to the candidate before hashing.

```bash
./brutecraber -f salted_suffix.txt -w rockyou.txt -t md5-salt-suffix
```

## Bcrypt

Bcrypt hashes are verified directly, not compared by hash output.

```bash
./brutecraber -f bcrypt_hashes.txt -w rockyou.txt -t bcrypt
```

## NTLM (Windows hashes)

```bash
./brutecraber -f ntlm_hashes.txt -w rockyou.txt -t ntlm
```

## PBKDF2-SHA256 (PHC format)

PBKDF2 auto-detection supports PHC records beginning with `$pbkdf2-sha256$`.

```bash
./brutecraber -f pbkdf2_hashes.txt -w wordlist.txt
```

## Base64 encoded hashes

If your hashes are Base64 encoded, use the `-base64` suffix. Standard Base64 with or without trailing `=` padding is accepted; specify the type explicitly.

```bash
./brutecraber -f base64_hashes.txt -w rockyou.txt -t sha256-base64
```

## GPU fallback

GPU kernels are used only for supported raw-hex types. Base64, salted and memory-hard types use CPU. OpenCL kernels support only single-block candidates: MD5/SHA-1/SHA-256 up to 55 bytes, SHA-512 up to 111, SHA3-256 up to 135, SHA3-512 up to 71, and NTLM up to 27 ASCII characters. Longer candidates and non-ASCII NTLM candidates fall back to CPU; GPU execution errors also retry on CPU.

## Hash file formats

### Standard (one hash per line)

Blank lines and full-line comments beginning with `#` are ignored.

```
5f4dcc3b5aa765d61d8327deb882cf99
e10adc3949ba59abbe56e057f20f883e
```

### Salted (salt:hash per line)

```
abc123:5f4dcc3b5aa765d61d8327deb882cf99
mysalt:e10adc3949ba59abbe56e057f20f883e
```

### Username-prefixed raw hashes

Use an explicit `-t` type; the final colon-delimited field is treated as the hash.

```
alice:5f4dcc3b5aa765d61d8327deb882cf99
```

```bash
./brutecraber -f user_hashes.txt -w wordlist.txt -t md5
```

### Hash followed by salt (`hash:salt`)

Use the matching `-salt-suffix` type. This mode computes `hash(candidate + salt)`.

```
9af87eabc21c318d6839aea39d5156bb:x7k2
```

Raw SHA-512 (`sha512`) is not Unix SHA-512-crypt (`$6$`). SHA-512-crypt and other `crypt` formats are not currently supported.

### Bcrypt

```
$2b$12$LJ3m4ys3Lg2VBe5E5APrie0rKMfONBIHEJCLa2rFfl2JHsyPVr3ZW
```
