use bcrypt::verify;

pub fn is_valid_hash_format(hash: &str) -> bool {
    let bytes = hash.as_bytes();
    let supported_version = ["$2a$", "$2b$", "$2y$"]
        .iter()
        .any(|prefix| hash.starts_with(prefix));

    if bytes.len() != 60
        || !supported_version
        || !bytes[4].is_ascii_digit()
        || !bytes[5].is_ascii_digit()
        || bytes[6] != b'$'
    {
        return false;
    }

    let cost = usize::from(bytes[4] - b'0') * 10 + usize::from(bytes[5] - b'0');

    (4..=31).contains(&cost)
        && bytes[7..].iter().all(|byte| {
            matches!(
                *byte,
                b'.' | b'/' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
            )
        })
}

// verify returns bool!
pub fn crack(word: &str, hash: &str) -> bool {
    verify(word, hash).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack_valid() {
        assert!(crack(
            "password",
            "$2y$04$xa4SIvcnMqIWtM8LZt3/2eoi5AsfZdM.wstwCsGVXDHSVY6Egv9rm"
        ));
        assert!(crack(
            "admin",
            "$2y$04$E4S23BqwqDr.QYpl7sHCze61WXTTZbzd3mNZccwd3qHbFsc8yUqhq"
        ));
    }

    #[test]
    fn test_crack_invalid() {
        assert!(!crack(
            "wrongpassword",
            "$2y$04$xa4SIvcnMqIWtM8LZt3/2eoi5AsfZdM.wstwCsGVXDHSVY6Egv9rm"
        ));
    }
}
