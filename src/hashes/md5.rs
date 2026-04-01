use md5::{Digest, Md5};

pub fn crack(word: &str) -> String {
    let mut hash_engine = Md5::new();
    hash_engine.update(word);
    format!("{:x}", hash_engine.finalize())
}

pub fn crack_with_salt(word: &str, salt: &str) -> String {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Md5::new();
    hash_engine.update(salted);
    format!("{:x}", hash_engine.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack() {
        assert_eq!(crack("password"), "5f4dcc3b5aa765d61d8327deb882cf99");
        assert_eq!(crack("admin"), "21232f297a57a5a743894a0e4a801fc3");
    }

    #[test]
    fn test_crack_with_salt() {
        assert_eq!(crack_with_salt("password", "x7k2"), "86f75bc83edcd705c834c436f6b64fdc");
        assert_eq!(crack_with_salt("admin", "r9f1"), "646f865e5ec771044931d7b00f4f2c25");
    }
}
