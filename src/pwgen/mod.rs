pub mod config;
pub mod generator;

pub use config::PasswordConfig;
pub use generator::generate_password;

/// Character sets for password generation
pub struct CharacterSets {
    /// Lowercase letters: a-z
    pub lowercase: &'static str,
    /// Uppercase letters: A-Z
    pub uppercase: &'static str,
    /// Numeric digits: 0-9
    pub digits: &'static str,
    /// Special characters
    pub symbols: &'static str,
}

/// Default character sets for password generation
pub const DEFAULT_CHARSETS: CharacterSets = CharacterSets {
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!@#$%&.-_*",
};

/// Ambiguous characters to be avoided if `avoid_ambiguous` is enabled
pub const AMBIGUOUS_CHARS: &str = "0O1Il5S";
