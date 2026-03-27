use bcrypt::verify;

// verify returns bool!
pub fn crack(word: &str, hash: &str) -> bool {
    verify(word, hash).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack_valid() {
        assert!(crack("password", "$2y$04$xa4SIvcnMqIWtM8LZt3/2eoi5AsfZdM.wstwCsGVXDHSVY6Egv9rm"));
        assert!(crack("admin", "$2y$04$E4S23BqwqDr.QYpl7sHCze61WXTTZbzd3mNZccwd3qHbFsc8yUqhq"));
    }

    #[test]
    fn test_crack_invalid() {
        assert!(!crack("wrongpassword", "$2y$04$xa4SIvcnMqIWtM8LZt3/2eoi5AsfZdM.wstwCsGVXDHSVY6Egv9rm"));
    }
}
