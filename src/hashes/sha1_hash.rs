use sha1::{Digest, Sha1};

pub fn crack(word: &str) -> String {
    let mut hash_engine = Sha1::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}

pub fn crack_with_salt(word: &str, salt: &str) -> String {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Sha1::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}
