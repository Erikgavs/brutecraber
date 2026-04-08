use md4::{Digest, Md4};

pub fn crack(word: &str) -> [u8; 16] {
    let winencode: Vec<u8> = word.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let mut hasher = Md4::new();
    hasher.update(&winencode);
    hasher.finalize().into()
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
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
        assert_eq!(
            bytes_to_hex(&crack("admin")),
            "209c6174da490caeb422f3fa5a7ae634"
        );
    }
}
