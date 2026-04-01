use sha3::{Digest, Sha3_256};

pub fn crack(word: &str) -> String {
    let mut hash_engine = Sha3_256::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}

pub fn crack_with_salt(word: &str, salt: &str) -> String {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Sha3_256::new();
    hash_engine.update(salted);
    format!("{:x}", hash_engine.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack() {
        // echo -n password | sha3-256sum
        assert_eq!(crack("password"), "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484");
        assert_eq!(crack("admin"), "fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b");
    }

    #[test]
    fn test_crack_with_salt() {
        assert_eq!(crack_with_salt("password", "x7k2"), "a4b91e1006e60758ffe90df79580b5b15fd37ab6e6a49a8c03939beff5a61e3a");
    }
}
