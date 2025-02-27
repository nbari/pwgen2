use crate::pwgen::{config::PasswordConfig, AMBIGUOUS_CHARS, DEFAULT_CHARSETS};
use rand::{rng, seq::SliceRandom, Rng};
use std::collections::HashSet;

/// Generates a password based on the given configuration
pub fn generate_password(config: &PasswordConfig) -> String {
    let mut rng = rng();
    let mut charset = String::new();
    let mut password = Vec::with_capacity(config.length.into());

    let filtered_lowercase: String = DEFAULT_CHARSETS
        .lowercase
        .chars()
        .filter(|c| !config.avoid_ambiguous || !AMBIGUOUS_CHARS.contains(*c))
        .collect();

    let filtered_uppercase: String = DEFAULT_CHARSETS
        .uppercase
        .chars()
        .filter(|c| !config.avoid_ambiguous || !AMBIGUOUS_CHARS.contains(*c))
        .collect();

    let filtered_digits: String = DEFAULT_CHARSETS
        .digits
        .chars()
        .filter(|c| !config.avoid_ambiguous || !AMBIGUOUS_CHARS.contains(*c))
        .collect();

    let filtered_symbols: String = if config.include_symbols {
        DEFAULT_CHARSETS.symbols.to_string()
    } else {
        String::new()
    };

    charset.push_str(&filtered_symbols);

    if config.include_lowercase && !filtered_lowercase.is_empty() {
        password.push(
            filtered_lowercase
                .chars()
                .nth(rng.random_range(0..filtered_lowercase.len()))
                .unwrap(),
        );
        charset.push_str(&filtered_lowercase);
    }

    if config.include_uppercase && !filtered_uppercase.is_empty() {
        password.push(
            filtered_uppercase
                .chars()
                .nth(rng.random_range(0..filtered_uppercase.len()))
                .unwrap(),
        );
        charset.push_str(&filtered_uppercase);
    }

    if config.include_digits && !filtered_digits.is_empty() {
        password.push(
            filtered_digits
                .chars()
                .nth(rng.random_range(0..filtered_digits.len()))
                .unwrap(),
        );
        charset.push_str(&filtered_digits);
    }

    let charset_chars: Vec<char> = charset.chars().collect();
    let symbols: HashSet<char> = filtered_symbols.chars().collect();

    let mut symbol_count = 0;
    if config.include_symbols && !filtered_symbols.is_empty() {
        let symbol = filtered_symbols
            .chars()
            .nth(rng.random_range(0..filtered_symbols.len()))
            .unwrap();
        password.push(symbol);
        symbol_count += 1;
    }

    // Calculate maximum allowed symbols (1 per 10 characters, rounded up)
    let max_symbols = if config.include_symbols {
        (config.length as f32 / 10.0).ceil() as u8
    } else {
        0
    };

    // Prepare symbol tracking
    let (symbol_charset, non_symbol_charset): (Vec<_>, Vec<_>) =
        charset_chars.iter().partition(|c| symbols.contains(c));

    // Fill remaining characters with symbol balance
    while password.len() < config.length.into() {
        let remaining = config.length.saturating_sub(password.len() as u8);
        let available_symbol_slots = max_symbols.saturating_sub(symbol_count);

        // Prefer non-symbols if we have more slots than remaining characters
        let use_symbol = available_symbol_slots > 0
            && (remaining <= available_symbol_slots || rng.random_bool(0.3));

        let c = if use_symbol && !filtered_symbols.is_empty() {
            *symbol_charset
                .get(rng.random_range(0..symbol_charset.len()))
                .unwrap_or(&'~') // Fallback if empty
        } else {
            *non_symbol_charset
                .get(rng.random_range(0..non_symbol_charset.len()))
                .unwrap_or(&'a') // Fallback if empty
        };

        if symbols.contains(&c) {
            symbol_count += 1;
        }
        password.push(c);
    }

    password.shuffle(&mut rng);

    if symbols.contains(&password[0]) {
        if let Some(non_symbol_index) = password.iter().position(|c| !symbols.contains(c)) {
            password.swap(0, non_symbol_index);
        }
    }

    password.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password() {
        let config = PasswordConfig::new(16).unwrap();
        let password = generate_password(&config);

        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_password_with_symbols() {
        let config = PasswordConfig::new(16)
            .unwrap()
            .with_symbols(true)
            .with_avoid_ambiguous(true);
        let password = generate_password(&config);

        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_password_with_symbols_and_lowercase() {
        let config = PasswordConfig::new(16)
            .unwrap()
            .with_symbols(true)
            .with_lowercase(true)
            .with_avoid_ambiguous(true);
        let password = generate_password(&config);

        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_password_with_symbols_and_uppercase() {
        let config = PasswordConfig::new(16)
            .unwrap()
            .with_symbols(true)
            .with_uppercase(true)
            .with_avoid_ambiguous(true);
        let password = generate_password(&config);

        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_password_with_symbols_and_digits() {
        let config = PasswordConfig::new(16)
            .unwrap()
            .with_symbols(true)
            .with_digits(true)
            .with_avoid_ambiguous(true);
        let password = generate_password(&config);

        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_password_with_symbols_and_lowercase_and_uppercase() {
        let config = PasswordConfig::new(16)
            .unwrap()
            .with_symbols(true)
            .with_lowercase(true)
            .with_uppercase(true)
            .with_avoid_ambiguous(true);
        let password = generate_password(&config);

        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_password_with_symbols_and_lowercase_and_digits() {
        let config = PasswordConfig::new(16)
            .unwrap()
            .with_symbols(true)
            .with_lowercase(true)
            .with_digits(true)
            .with_avoid_ambiguous(true);
        let password = generate_password(&config);

        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_password_does_not_start_with_symbol() {
        let config = PasswordConfig {
            length: 64,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            avoid_ambiguous: false,
        };

        for _ in 0..1000 {
            let password = generate_password(&config);
            let symbols: HashSet<char> = DEFAULT_CHARSETS.symbols.chars().collect();
            assert!(
                !symbols.contains(&password.chars().next().unwrap()),
                "Password started with a symbol: {}",
                password
            );
        }
    }
}
