use sha2::{Digest, Sha256};

pub fn crack(word: &str) -> String {
    let mut hash_engine = Sha256::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}
