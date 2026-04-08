use md5::{Digest, Md5};

pub fn crack(word: &str) -> [u8; 16] {
    let mut hash_engine = Md5::new();
    hash_engine.update(word);
    hash_engine.finalize().into()
}

pub fn crack_with_salt(word: &str, salt: &str) -> [u8; 16] {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Md5::new();
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
            "5f4dcc3b5aa765d61d8327deb882cf99"
        );
        assert_eq!(
            bytes_to_hex(&crack("admin")),
            "21232f297a57a5a743894a0e4a801fc3"
        );
    }

    #[test]
    fn test_crack_with_salt() {
        assert_eq!(
            bytes_to_hex(&crack_with_salt("password", "x7k2")),
            "86f75bc83edcd705c834c436f6b64fdc"
        );
        assert_eq!(
            bytes_to_hex(&crack_with_salt("admin", "r9f1")),
            "646f865e5ec771044931d7b00f4f2c25"
        );
    }
}
