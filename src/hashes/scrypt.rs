use scrypt::{
    Scrypt,
    password_hash::{PasswordHash, PasswordVerifier},
};

pub fn is_valid_hash_format(hash: &str) -> bool {
    hash.starts_with("$scrypt$") && PasswordHash::new(hash).is_ok()
}

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

    const LOW_COST_FIXTURES: &str = include_str!("../../tests/hashes/scrypt/hashes.txt");

    fn fixture_hash(index: usize) -> &'static str {
        LOW_COST_FIXTURES
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .nth(index)
            .expect("missing Scrypt test fixture")
    }

    fn generate_default_cost_hash(password: &str, salt: &str) -> String {
        let salt = SaltString::from_b64(salt).unwrap();
        Scrypt
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    #[test]
    fn test_verify_valid() {
        assert!(verify("password", fixture_hash(0)));
    }

    #[test]
    fn test_verify_invalid() {
        assert!(!verify("wrongpassword", fixture_hash(0)));
    }

    #[test]
    fn test_verify_admin() {
        assert!(verify("admin", fixture_hash(1)));
        assert!(!verify("administrator", fixture_hash(1)));
    }

    #[test]
    fn test_invalid_hash_format() {
        assert!(!verify("password", "invalid_hash"));
        assert!(!verify("password", "$scrypt$invalid"));
    }

    #[test]
    #[ignore = "slow default-cost Scrypt check; run explicitly when needed"]
    fn slow_default_cost_scrypt_round_trip() {
        let hash = generate_default_cost_hash("password", "c29tZXNhbHQ");
        assert!(verify("password", &hash));
    }
}
