pub fn detect(hash: &str) -> &str {
    if hash.starts_with("$scrypt") {
        return "scrypt";
    }

    if hash.starts_with("$argon2") {
        return "argon2";
    }

    if hash.starts_with("$2") {
        return "bcrypt";
    }

    match hash.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256/sha3-256",
        128 => "sha512/sha3-512",
        _ => "hash not recognized, try using -t parameter",
    }
}
