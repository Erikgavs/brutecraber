use sha2::{Digest, Sha512};

pub fn crack(word: &str) -> [u8; 64] {
    let mut hash_engine = Sha512::new();
    hash_engine.update(word);
    hash_engine.finalize().into()
}

pub fn crack_with_salt(word: &str, salt: &str) -> [u8; 64] {
    let salted = format!("{}{}", salt, word);
    let mut hash_engine = Sha512::new();
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
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
        );
        assert_eq!(
            bytes_to_hex(&crack("admin")),
            "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
        );
    }

    #[test]
    fn test_crack_with_salt() {
        assert_eq!(
            bytes_to_hex(&crack_with_salt("password", "x7k2")),
            "16840f66c91412ad31d522935d66b54d423c4f240aca10480cef20436a11d119e29ad82b761e8eafb8abf2bfabbe0aebb4732c76267225f6ad178d8896a9018f"
        );
        assert_eq!(
            bytes_to_hex(&crack_with_salt("admin", "r9f1")),
            "7e42c96c35b99d814b548fcf3cbdf65af998e2be9422c51c50d0dab2cbf2c370f6cf474ab9d8c1d4abb3189fea5c8ad9d3d67b2ca952e2b61b3024b6b0cdfebe"
        );
    }
}
