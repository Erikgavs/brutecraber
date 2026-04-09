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
