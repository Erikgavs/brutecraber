use sha2::{Digest, Sha256};

pub fn crack(word: &str) -> String {
    let mut hash_engine = Sha256::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}

pub fn crack_with_salt(word: &str, salt: &str) -> String {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Sha256::new();
    hash_engine.update(salted);
    format!("{:x}", hash_engine.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack() {
        assert_eq!(
            crack("password"),
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
        assert_eq!(
            crack("admin"),
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
        );
    }

    #[test]
    fn test_crack_with_salt() {
        assert_eq!(
            crack_with_salt("password", "x7k2"),
            "ab8182cc945620b02e1bca27accc51809b2a5fca67f576823c0044b09ee693c8"
        );
        assert_eq!(
            crack_with_salt("admin", "r9f1"),
            "540ac55f5dbdf15fa2e72a45ce0e17c72ab80b2633a44c8f699c6d1f3a393380"
        );
    }
}
