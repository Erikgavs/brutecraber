use sha1::{Digest, Sha1};

pub fn crack(word: &str) -> String {
    let mut hash_engine = Sha1::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}
