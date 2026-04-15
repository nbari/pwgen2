use anyhow::{Context, Result};
use bcrypt::{DEFAULT_COST, hash, verify};
use pbkdf2::{
    Pbkdf2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use sha_crypt::{Sha512Params, sha512_check, sha512_simple};

/// Hashes a password using bcrypt.
///
/// # Errors
///
/// Returns an error if bcrypt hashing fails.
pub fn hash_bcrypt(password: &str) -> Result<String> {
    hash(password, DEFAULT_COST).context("Failed to hash password using bcrypt")
}

/// Verifies a password against a bcrypt hash.
///
/// # Errors
///
/// Returns an error if bcrypt verification fails.
pub fn verify_bcrypt(password: &str, hashed: &str) -> Result<bool> {
    verify(password, hashed).context("Failed to verify bcrypt password")
}

/// Hashes a password using PBKDF2.
///
/// # Errors
///
/// Returns an error if PBKDF2 hashing fails.
pub fn hash_pbkdf2(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Pbkdf2
        .hash_password(password.as_bytes(), &salt)
        .context("Failed to hash password using PBKDF2")?;

    Ok(password_hash.to_string())
}

/// Verifies a password against a PBKDF2 hash.
///
/// # Errors
///
/// Returns an error if the hash cannot be parsed or verification fails.
pub fn verify_pbkdf2(password: &str, hashed: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hashed).context("Failed to parse PBKDF2 hash")?;

    Ok(Pbkdf2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Hashes a password using SHA-512 crypt.
///
/// # Errors
///
/// Returns an error if SHA-512 crypt parameter creation or hashing fails.
pub fn hash_sha512(password: &str) -> Result<String> {
    let params = Sha512Params::new(sha_crypt::ROUNDS_DEFAULT)
        .map_err(|err| anyhow::anyhow!("Failed to create SHA-512 params: {err:?}"))?;

    sha512_simple(password, &params)
        .map_err(|err| anyhow::anyhow!("Failed to hash password using SHA-512 crypt: {err:?}"))
}

/// Verifies a password against a SHA-512 crypt hash.
///
/// # Errors
///
/// Returns an error if SHA-512 crypt verification fails.
pub fn verify_sha512(password: &str, hashed: &str) -> Result<bool> {
    Ok(sha512_check(password, hashed).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_hash_bcrypt() -> Result<()> {
        let password = "password";
        let hashed = hash_bcrypt(password)?;
        assert!(verify_bcrypt(password, &hashed)?);
        Ok(())
    }

    #[test]
    fn test_hash_pbkdf2() -> Result<()> {
        let password = "password";
        let hashed = hash_pbkdf2(password)?;
        assert!(verify_pbkdf2(password, &hashed)?);
        Ok(())
    }

    #[test]
    fn test_hash_sha512() -> Result<()> {
        let password = "password";
        let hashed = hash_sha512(password)?;
        assert!(verify_sha512(password, &hashed)?);
        Ok(())
    }
}
