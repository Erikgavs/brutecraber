use sha3::{Digest, Sha3_512};

pub fn crack(word: &str) -> [u8; 64] {
    let mut hash_engine = Sha3_512::new();
    hash_engine.update(word);
    hash_engine.finalize().into()
}

pub fn crack_with_salt(word: &str, salt: &str) -> [u8; 64] {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Sha3_512::new();
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
        // echo -n password | openssl dgst -sha3-512
        assert_eq!(
            bytes_to_hex(&crack("password")),
            "e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
        );
        assert_eq!(
            bytes_to_hex(&crack("admin")),
            "5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
        );
    }

    #[test]
    fn test_crack_with_salt() {
        assert_eq!(
            bytes_to_hex(&crack_with_salt("password", "x7k2")),
            "0154e9b9d5509ef2bf78fb2ac017a51d5c8ef9f7e4596eef7174bda271b93289a959878edc4a144a0943d9a18db6c77391089290747235f62a111958ed47b91a"
        );
    }
}
