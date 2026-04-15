use crate::pwgen::config::{CharacterPools, PasswordConfig, PasswordConfigError};
use rand::{RngExt, rng, seq::SliceRandom};
use std::collections::HashSet;

fn random_char(
    rng: &mut impl RngExt,
    chars: &[char],
    pool_name: &'static str,
) -> Result<char, PasswordConfigError> {
    if chars.is_empty() {
        return Err(PasswordConfigError::EmptyCharacterPool(pool_name));
    }

    chars
        .get(rng.random_range(0..chars.len()))
        .copied()
        .ok_or(PasswordConfigError::EmptyCharacterPool(pool_name))
}

fn append_required_characters(
    rng: &mut impl RngExt,
    password: &mut Vec<char>,
    charset: &mut Vec<char>,
    pools: &CharacterPools,
) -> Result<(), PasswordConfigError> {
    if !pools.lowercase.is_empty() {
        password.push(random_char(rng, &pools.lowercase, "lowercase")?);
        charset.extend_from_slice(&pools.lowercase);
    }

    if !pools.uppercase.is_empty() {
        password.push(random_char(rng, &pools.uppercase, "uppercase")?);
        charset.extend_from_slice(&pools.uppercase);
    }

    if !pools.digits.is_empty() {
        password.push(random_char(rng, &pools.digits, "digits")?);
        charset.extend_from_slice(&pools.digits);
    }

    Ok(())
}

/// Generates a password based on the given configuration.
///
/// Passwords keep symbols sparse and never start with a symbol.
///
/// # Errors
///
/// Returns a [`PasswordConfigError`] when the configuration cannot produce a
/// password that satisfies the generator's rules.
pub fn generate_password(config: &PasswordConfig) -> Result<String, PasswordConfigError> {
    let pools = config.character_pools()?;
    let mut rng = rng();
    let mut charset = Vec::new();
    let mut password = Vec::with_capacity(usize::from(config.length));

    charset.extend_from_slice(&pools.symbols);
    append_required_characters(&mut rng, &mut password, &mut charset, &pools)?;

    let symbols: HashSet<char> = pools.symbols.iter().copied().collect();
    let mut symbol_count = 0;

    if !pools.symbols.is_empty() {
        password.push(random_char(&mut rng, &pools.symbols, "symbols")?);
        symbol_count += 1;
    }

    let max_symbols = if pools.symbols.is_empty() {
        0
    } else {
        usize::from(config.length).div_ceil(10)
    };

    let symbol_charset: Vec<char> = charset
        .iter()
        .copied()
        .filter(|c| symbols.contains(c))
        .collect();
    let non_symbol_charset: Vec<char> = charset
        .iter()
        .copied()
        .filter(|c| !symbols.contains(c))
        .collect();

    while password.len() < usize::from(config.length) {
        let remaining = usize::from(config.length) - password.len();
        let available_symbol_slots = max_symbols.saturating_sub(symbol_count);

        let use_symbol = available_symbol_slots > 0
            && (remaining <= available_symbol_slots || rng.random_bool(0.3));

        let next_char = if use_symbol {
            random_char(&mut rng, &symbol_charset, "symbols")?
        } else {
            random_char(&mut rng, &non_symbol_charset, "non-symbols")?
        };

        if symbols.contains(&next_char) {
            symbol_count += 1;
        }

        password.push(next_char);
    }

    password.shuffle(&mut rng);

    if let Some(first_char) = password.first()
        && symbols.contains(first_char)
        && let Some(non_symbol_index) = password.iter().position(|c| !symbols.contains(c))
    {
        password.swap(0, non_symbol_index);
    }

    Ok(password.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pwgen::config::{AmbiguousCharacterPolicy, CharacterSetSelection};
    use crate::pwgen::{AMBIGUOUS_CHARS, DEFAULT_CHARSETS};
    use anyhow::{Result, anyhow};

    fn default_symbols() -> HashSet<char> {
        DEFAULT_CHARSETS.symbols.chars().collect()
    }

    #[test]
    fn test_generate_password() -> Result<()> {
        let config = PasswordConfig::new(16)?;
        let password = generate_password(&config)?;

        assert_eq!(password.len(), 16);
        Ok(())
    }

    #[test]
    fn test_generate_password_with_symbols() -> Result<()> {
        let config = PasswordConfig::new(16)?
            .with_symbols(true)
            .with_avoid_ambiguous(true);
        let password = generate_password(&config)?;

        assert_eq!(password.len(), 16);
        Ok(())
    }

    #[test]
    fn test_password_does_not_start_with_symbol() -> Result<()> {
        let config = PasswordConfig {
            length: 64,
            charset: None,
            include_lowercase: CharacterSetSelection::Include,
            include_uppercase: CharacterSetSelection::Include,
            include_digits: CharacterSetSelection::Include,
            include_symbols: CharacterSetSelection::Include,
            avoid_ambiguous: AmbiguousCharacterPolicy::Allow,
        };
        let symbols = default_symbols();

        for _ in 0..1000 {
            let password = generate_password(&config)?;
            let first_char = password
                .chars()
                .next()
                .ok_or_else(|| anyhow!("generated password should not be empty"))?;
            assert!(
                !symbols.contains(&first_char),
                "Password started with a symbol: {password}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_password_does_not_contain_ambiguous_chars() -> Result<()> {
        let config = PasswordConfig {
            length: 64,
            charset: None,
            include_lowercase: CharacterSetSelection::Include,
            include_uppercase: CharacterSetSelection::Include,
            include_digits: CharacterSetSelection::Include,
            include_symbols: CharacterSetSelection::Include,
            avoid_ambiguous: AmbiguousCharacterPolicy::Avoid,
        };

        for _ in 0..1000 {
            let password = generate_password(&config)?;
            assert!(
                !password.chars().any(|c| AMBIGUOUS_CHARS.contains(c)),
                "Password contained ambiguous characters: {password}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_password_contains_symbols() -> Result<()> {
        let config = PasswordConfig {
            length: 64,
            charset: None,
            include_lowercase: CharacterSetSelection::Include,
            include_uppercase: CharacterSetSelection::Include,
            include_digits: CharacterSetSelection::Include,
            include_symbols: CharacterSetSelection::Include,
            avoid_ambiguous: AmbiguousCharacterPolicy::Allow,
        };
        let symbols = default_symbols();

        for _ in 0..1000 {
            let password = generate_password(&config)?;
            assert!(
                password.chars().any(|c| symbols.contains(&c)),
                "Password did not contain symbols: {password}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_password_limits_symbol_density() -> Result<()> {
        let config = PasswordConfig::new(64)?;
        let symbols = default_symbols();

        for _ in 0..1000 {
            let password = generate_password(&config)?;
            let symbol_count = password.chars().filter(|c| symbols.contains(c)).count();
            assert!(
                symbol_count <= 7,
                "Password exceeded symbol policy: {password}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_password_containing_custom_charset() -> Result<()> {
        let config = PasswordConfig::custom(18, "~".to_string())?;

        for _ in 0..1000 {
            let password = generate_password(&config)?;
            assert!(password.chars().any(|c| c == '~'));
        }
        Ok(())
    }

    #[test]
    fn test_password_containing_multibyte_custom_charset() -> Result<()> {
        let config = PasswordConfig::custom(18, "€".to_string())?;

        for _ in 0..100 {
            let password = generate_password(&config)?;
            assert!(password.chars().any(|c| c == '€'));
        }
        Ok(())
    }

    #[test]
    fn test_empty_custom_charset_is_invalid() -> Result<()> {
        let config = PasswordConfig::custom(18, String::new())?;
        let result = generate_password(&config);

        assert!(matches!(
            result,
            Err(PasswordConfigError::EmptyCustomCharset)
        ));
        Ok(())
    }

    #[test]
    fn test_only_symbols_config_is_invalid() -> Result<()> {
        let config = PasswordConfig::new(16)?
            .with_lowercase(false)
            .with_uppercase(false)
            .with_digits(false);
        let result = generate_password(&config);

        assert!(matches!(
            result,
            Err(PasswordConfigError::MissingNonSymbolCharacters)
        ));
        Ok(())
    }
}
