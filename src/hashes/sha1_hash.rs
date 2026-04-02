use sha1::{Digest, Sha1};

pub fn crack(word: &str) -> String {
    let mut hash_engine = Sha1::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}

pub fn crack_with_salt(word: &str, salt: &str) -> String {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Sha1::new();
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
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        );
        assert_eq!(crack("admin"), "d033e22ae348aeb5660fc2140aec35850c4da997");
    }

    #[test]
    fn test_crack_with_salt() {
        assert_eq!(
            crack_with_salt("password", "x7k2"),
            "4b7f88df9bc5e48e1e5bd3ad9bb1cc54e54ba68d"
        );
        assert_eq!(
            crack_with_salt("admin", "r9f1"),
            "e194058e96824437b6d65dfa7a05d5956446e8fb"
        );
    }
}
