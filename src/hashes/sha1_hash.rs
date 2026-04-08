use sha1::{Digest, Sha1};

pub fn crack(word: &str) -> [u8; 20] {
    let mut hash_engine = Sha1::new();
    hash_engine.update(word);
    hash_engine.finalize().into()
}

pub fn crack_with_salt(word: &str, salt: &str) -> [u8; 20] {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Sha1::new();
    hash_engine.update(salted);
    hash_engine.finalize().into()
}

#[cfg(test)]
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack() {
        assert_eq!(
            bytes_to_hex(&crack("password")),
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        );
        assert_eq!(
            bytes_to_hex(&crack("admin")),
            "d033e22ae348aeb5660fc2140aec35850c4da997"
        );
    }

    #[test]
    fn test_crack_with_salt() {
        assert_eq!(
            bytes_to_hex(&crack_with_salt("password", "x7k2")),
            "4b7f88df9bc5e48e1e5bd3ad9bb1cc54e54ba68d"
        );
        assert_eq!(
            bytes_to_hex(&crack_with_salt("admin", "r9f1")),
            "e194058e96824437b6d65dfa7a05d5956446e8fb"
        );
    }
}
