use anyhow::{Context, Result};
use bip39::Mnemonic;

/// Generates a standard BIP-39 mnemonic phrase.
///
/// # Errors
///
/// Returns an error if the requested word count is invalid or mnemonic
/// generation fails.
pub fn generate_mnemonic(word_count: usize) -> Result<String> {
    let mnemonic =
        Mnemonic::generate(word_count).context("Failed to generate BIP-39 mnemonic phrase")?;

    Ok(mnemonic.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use bip39::{Language, Mnemonic};

    #[test]
    fn test_generate_mnemonic_default_word_count() -> Result<()> {
        let phrase = generate_mnemonic(12)?;

        assert_eq!(phrase.split_whitespace().count(), 12);
        assert!(Mnemonic::parse_in_normalized(Language::English, &phrase).is_ok());
        Ok(())
    }

    #[test]
    fn test_generate_mnemonic_rejects_invalid_count() {
        assert!(generate_mnemonic(14).is_err());
    }
}
