use anyhow::{Context, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use pbkdf2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use sha_crypt::{sha512_check, sha512_simple, Sha512Params};

/// Hash a password using bcrypt
pub fn hash_bcrypt(password: &str) -> Result<String> {
    hash(password, DEFAULT_COST).context("Failed to hash password using bcrypt")
}

/// Verify a password against a bcrypt hash
pub fn verify_bcrypt(password: &str, hashed: &str) -> Result<bool> {
    verify(password, hashed).context("Failed to verify bcrypt password")
}

/// Hash a password using PBKDF2
pub fn hash_pbkdf2(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Pbkdf2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password using PBKDF2");
    Ok(password_hash.to_string())
}

/// Verify a password against a PBKDF2 hash
pub fn verify_pbkdf2(password: &str, hashed: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hashed).expect("Failed to parse PBKDF2 hash");
    Ok(Pbkdf2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn hash_sha512(password: &str) -> Result<String> {
    let params = Sha512Params::new(sha_crypt::ROUNDS_DEFAULT).expect("RandomError!");

    Ok(sha512_simple(password, &params).expect("hashing error"))
}

pub fn verify_sha512(password: &str, hashed: &str) -> Result<bool> {
    Ok(sha512_check(password, hashed).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bcrypt() {
        let password = "password";
        let hashed = hash_bcrypt(password).unwrap();
        assert!(verify_bcrypt(password, &hashed).unwrap());
    }

    #[test]
    fn test_hash_pbkdf2() {
        let password = "password";
        let hashed = hash_pbkdf2(password).unwrap();
        assert!(verify_pbkdf2(password, &hashed).unwrap());
    }

    #[test]
    fn test_hash_sha512() {
        let password = "password";
        let hashed = hash_sha512(password).unwrap();
        assert!(verify_sha512(password, &hashed).unwrap());
    }
}
