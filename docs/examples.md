# Examples
> This documentation applies to brutecraber v0.7.0

> This project is under active development

## Basic usage with auto-detection

The tool will automatically detect the hash type based on the first hash in the file.

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

The hash file must use the `salt:hash` format, one per line.

```bash
./brutecraber -f salted.txt -w rockyou.txt -t md5-salt
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

## Base64 encoded hashes

If your hashes are Base64 encoded, use the `-base64` suffix.

```bash
./brutecraber -f base64_hashes.txt -w rockyou.txt -t sha256-base64
```

## Hash file formats

### Standard (one hash per line)

```
5f4dcc3b5aa765d61d8327deb882cf99
e10adc3949ba59abbe56e057f20f883e
```

### Salted (salt:hash per line)

```
abc123:5f4dcc3b5aa765d61d8327deb882cf99
mysalt:e10adc3949ba59abbe56e057f20f883e
```

### Bcrypt

```
$2b$12$LJ3m4ys3Lg2VBe5E5APrie0rKMfONBIHEJCLa2rFfl2JHsyPVr3ZW
```
