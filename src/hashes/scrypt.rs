use scrypt::{
    Scrypt,
    password_hash::{PasswordHash, PasswordVerifier},
};

pub fn verify(word: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed_hash) => Scrypt
            .verify_password(word.as_bytes(), &parsed_hash)
            .is_ok(),

        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrypt::{
        Scrypt,
        password_hash::{PasswordHasher, SaltString},
    };

    fn generate_hash(password: &str, salt: &str) -> String {
        let salt = SaltString::from_b64(salt).unwrap();
        Scrypt
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    #[test]
    fn test_verify_valid() {
        let hash = generate_hash("password", "c29tZXNhbHQ");
        assert!(verify("password", &hash));
    }

    #[test]
    fn test_verify_invalid() {
        let hash = generate_hash("password", "c29tZXNhbHQ");
        assert!(!verify("wrongpassword", &hash));
    }

    #[test]
    fn test_verify_admin() {
        let hash = generate_hash("admin", "YW5vdGhlcnNhbHQ");
        assert!(verify("admin", &hash));
        assert!(!verify("administrator", &hash));
    }

    #[test]
    fn test_invalid_hash_format() {
        assert!(!verify("password", "invalid_hash"));
        assert!(!verify("password", "$scrypt$invalid"));
    }

    /// Helper to (re)generate the fixture file `tests/hashes/scrypt/hashes.txt`.
    /// Run with: `cargo test scrypt::tests::print_fixture_hashes -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_fixture_hashes() {
        let words = ["password", "admin", "123456"];
        let salts = ["c29tZXNhbHRhYmM", "YW5vdGhlcnNhbHQ", "dGhpcmRzYWx0YWI"];
        for (w, s) in words.iter().zip(salts.iter()) {
            println!("{}", generate_hash(w, s));
        }
    }
}
