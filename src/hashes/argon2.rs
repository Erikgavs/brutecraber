use argon2::{Argon2, PasswordHash, PasswordVerifier};

pub fn verify(word: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(word.as_bytes(), &parsed_hash)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString},
    };

    fn generate_hash(password: &str, salt: &str) -> String {
        let salt = SaltString::from_b64(salt).unwrap();
        let argon2 = Argon2::default();
        argon2
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
        assert!(!verify("password", "$argon2id$invalid"));
    }
}
