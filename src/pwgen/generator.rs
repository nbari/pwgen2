use crate::pwgen::config::PasswordConfig;
use rand::{Rng, rng};

/// Character sets for password generation
pub struct CharacterSets {
    /// Lowercase letters: a-z
    pub lowercase: &'static str,
    /// Uppercase letters: A-Z
    pub uppercase: &'static str,
    /// Numeric digits: 0-9
    pub digits: &'static str,
    /// Special characters: !@#$%^&*()_-+=<>?/{}[]~:;.
    pub symbols: &'static str,
}

/// Default character sets for password generation
pub const DEFAULT_CHARSETS: CharacterSets = CharacterSets {
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!@#$%^&*()_-+=<>?/{}[]~:;.",
};

/// Ambiguous characters to be avoided if `avoid_ambiguous` is enabled
pub const AMBIGUOUS_CHARS: &str = "l1IoO0";

/// Generates a password based on the given configuration
pub fn generate_password(config: &PasswordConfig) -> String {
    let mut charset = String::new();

    // Build character set based on configuration
    if config.include_lowercase {
        charset.push_str(DEFAULT_CHARSETS.lowercase);
    }

    if config.include_uppercase {
        charset.push_str(DEFAULT_CHARSETS.uppercase);
    }

    if config.include_digits {
        charset.push_str(DEFAULT_CHARSETS.digits);
    }

    if config.include_symbols {
        charset.push_str(DEFAULT_CHARSETS.symbols);
    }

    // Remove ambiguous characters if `avoid_ambiguous` is enabled
    let filtered_charset: String = if config.avoid_ambiguous {
        charset
            .chars()
            .filter(|c| !AMBIGUOUS_CHARS.contains(*c))
            .collect()
    } else {
        charset
    };

    // Default to full character set if none specified
    let final_charset = if filtered_charset.is_empty() {
        DEFAULT_CHARSETS.lowercase.to_owned()
            + DEFAULT_CHARSETS.uppercase
            + DEFAULT_CHARSETS.digits
            + DEFAULT_CHARSETS.symbols
    } else {
        filtered_charset
    };

    let charset_bytes = final_charset.as_bytes();
    let mut rng = rng();

    // Generate password ensuring at least one character from each set if required
    if config.require_from_each_set {
        return generate_with_requirements(config, &final_charset);
    }

    // Standard password generation without requirements
    (0..config.length)
        .map(|_| {
            let idx = rng.random_range(0..charset_bytes.len());
            charset_bytes[idx] as char
        })
        .collect()
}

/// Generates a password ensuring at least one character from each required set
fn generate_with_requirements(config: &PasswordConfig, charset: &str) -> String {
    let mut rng = rng();
    let mut password = Vec::with_capacity(config.length);

    // Filtered character sets
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
    let filtered_symbols: String = DEFAULT_CHARSETS.symbols.to_string();

    // Add at least one character from each required set
    if config.include_lowercase && !filtered_lowercase.is_empty() {
        password.push(
            filtered_lowercase
                .chars()
                .nth(rng.random_range(0..filtered_lowercase.len()))
                .unwrap(),
        );
    }
    if config.include_uppercase && !filtered_uppercase.is_empty() {
        password.push(
            filtered_uppercase
                .chars()
                .nth(rng.random_range(0..filtered_uppercase.len()))
                .unwrap(),
        );
    }
    if config.include_digits && !filtered_digits.is_empty() {
        password.push(
            filtered_digits
                .chars()
                .nth(rng.random_range(0..filtered_digits.len()))
                .unwrap(),
        );
    }
    if config.include_symbols {
        password.push(
            filtered_symbols
                .chars()
                .nth(rng.random_range(0..filtered_symbols.len()))
                .unwrap(),
        );
    }

    // Fill the rest with random characters
    let charset_bytes = charset.as_bytes();
    while password.len() < config.length {
        let idx = rng.random_range(0..charset_bytes.len());
        password.push(charset_bytes[idx] as char);
    }

    // Shuffle to avoid predictable patterns
    for i in 0..password.len() {
        let j = rng.random_range(0..password.len());
        password.swap(i, j);
    }

    password.into_iter().collect()
}
