pub const MD5_NTLM: &str = "md5/ntlm";
pub const UNKNOWN_HASH_TYPE: &str = "hash not recognized, try using -t parameter";

pub fn detect(hash: &str) -> &'static str {
    let hash = hash.trim().trim_start_matches('\u{feff}').trim();

    if hash.starts_with("WPA*01*") {
        return "wpa-pmkid";
    }

    if hash.starts_with("WPA*02*") {
        return "wpa-handshake";
    }

    if hash.starts_with("$scrypt") {
        return "scrypt";
    }

    if hash.starts_with("$argon2") {
        return "argon2";
    }

    if hash.starts_with("$pbkdf2-sha256$") {
        return "pbkdf2";
    }

    if hash.starts_with("$2") {
        return "bcrypt";
    }

    let is_hex = hash.bytes().all(|byte| byte.is_ascii_hexdigit());

    match (hash.len(), is_hex) {
        (32, true) => MD5_NTLM,
        (40, true) => "sha1",
        (64, true) => "sha256/sha3-256",
        (128, true) => "sha512/sha3-512",
        _ => UNKNOWN_HASH_TYPE,
    }
}
