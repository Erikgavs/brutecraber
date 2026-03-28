use md4::{Digest, Md4};

pub fn crack(word: &str) -> String {
    // Convert to windows encoding
    let winencode: Vec<u8> = word.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let mut hasher = Md4::new();
    hasher.update(&winencode);
    hasher
        .finalize()  // get hash as raw bytes [93, 65, 64, 42, ...]
        .iter()      // iterate each byte
        .map(|b| format!("{:02x}", b))  // convert each byte to hex: 93 -> "5d"
        .collect()   // join all: "5d41402a..."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack() {
        assert_eq!(crack("password"), "8846f7eaee8fb117ad06bdd830b7586c");
        assert_eq!(crack("admin"), "209c6174da490caeb422f3fa5a7ae634");
    }
}
