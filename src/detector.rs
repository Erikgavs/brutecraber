pub fn detect(hash: &str) -> &str {
    match hash.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256-auto",
        128 => "sha512",
        _ => "hash not recognized, try using -t parameter",
    }
}
