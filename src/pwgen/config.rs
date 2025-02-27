/// Error type for password configuration validation
#[derive(Debug)]
pub enum PasswordConfigError {
    ZeroLength,
    NoCharacterSetsEnabled,
    LengthTooShortForSets { length: usize, sets_count: usize },
    NotEnoughAvailableCharacters { length: usize, available: usize },
}

impl std::fmt::Display for PasswordConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroLength => write!(f, "Password length must be greater than 0."),
            Self::NoCharacterSetsEnabled => {
                write!(f, "At least one character set must be included.")
            }
            Self::LengthTooShortForSets { length, sets_count } => {
                write!(
                    f,
                    "Password length ({}) must be at least equal to the number of required character sets ({}).",
                    length, sets_count
                )
            }
            Self::NotEnoughAvailableCharacters { length, available } => {
                write!(
                    f,
                    "Password length ({}) is too long given the restricted character set ({} available characters after avoiding ambiguous ones).",
                    length, available
                )
            }
        }
    }
}

impl std::error::Error for PasswordConfigError {}

/// Configuration for password generation
#[derive(Debug, Clone)]
pub struct PasswordConfig {
    /// Length of the password to generate
    pub length: usize,

    /// Include lowercase letters (a-z)
    pub include_lowercase: bool,

    /// Include uppercase letters (A-Z)
    pub include_uppercase: bool,

    /// Include numeric digits (0-9)
    pub include_digits: bool,

    /// Include special symbols (!@#$%^&*()_-+=<>?/)
    pub include_symbols: bool,

    /// Avoid ambiguous characters (1, l, I, 0, O, etc.)
    pub avoid_ambiguous: bool,

    /// Require at least one character from each included set
    pub require_from_each_set: bool,
}

impl Default for PasswordConfig {
    /// Creates a default password configuration:
    /// - 18 characters long
    /// - Includes lowercase, uppercase, digits, and symbols
    /// - Avoids ambiguous characters
    /// - Requires at least one character from each included set
    fn default() -> Self {
        Self {
            length: 18,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            avoid_ambiguous: true,
            require_from_each_set: true,
        }
    }
}

impl PasswordConfig {
    /// Creates a new password configuration with the specified length
    /// and default settings for other options
    pub fn new(length: usize) -> Self {
        Self {
            length,
            ..Self::default()
        }
    }

    /// Creates a new password configuration for a strong password
    pub const fn strong(length: usize) -> Self {
        Self {
            length,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            avoid_ambiguous: false,
            require_from_each_set: true,
        }
    }

    /// Creates a new password configuration for a PIN
    pub const fn pin(length: usize) -> Self {
        Self {
            length,
            include_lowercase: false,
            include_uppercase: false,
            include_digits: true,
            include_symbols: false,
            avoid_ambiguous: false,
            require_from_each_set: false,
        }
    }

    /// Creates a new password configuration for a readable password
    pub const fn readable(length: usize) -> Self {
        Self {
            length,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: false,
            avoid_ambiguous: true,
            require_from_each_set: true,
        }
    }

    /// Builder method to set whether to include lowercase letters
    pub const fn with_lowercase(mut self, include: bool) -> Self {
        self.include_lowercase = include;
        self
    }

    /// Builder method to set whether to include uppercase letters
    pub const fn with_uppercase(mut self, include: bool) -> Self {
        self.include_uppercase = include;
        self
    }

    /// Builder method to set whether to include digits
    pub const fn with_digits(mut self, include: bool) -> Self {
        self.include_digits = include;
        self
    }

    /// Builder method to set whether to include symbols
    pub const fn with_symbols(mut self, include: bool) -> Self {
        self.include_symbols = include;
        self
    }

    /// Builder method to set whether to avoid ambiguous characters
    pub const fn with_avoid_ambiguous(mut self, avoid: bool) -> Self {
        self.avoid_ambiguous = avoid;
        self
    }

    /// Builder method to set whether to require characters from each included set
    pub const fn with_require_from_each_set(mut self, require: bool) -> Self {
        self.require_from_each_set = require;
        self
    }

    /// Returns the number of available characters based on configuration
    const fn get_available_characters_count(&self) -> usize {
        let lowercase = if self.include_lowercase { 26 } else { 0 };
        let uppercase = if self.include_uppercase { 26 } else { 0 };
        let digits = if self.include_digits { 10 } else { 0 };
        let symbols = if self.include_symbols { 16 } else { 0 }; // Adjust based on your symbol set

        let mut total_chars: usize = lowercase + uppercase + digits + symbols;

        // If avoiding ambiguous characters, remove them from the count
        if self.avoid_ambiguous {
            let ambiguous_count = 8; // Approximate count of '1', 'l', 'I', '0', 'O', etc.
            total_chars = total_chars.saturating_sub(ambiguous_count);
        }

        total_chars
    }

    /// Validates the configuration
    pub const fn validate(&self) -> Result<(), PasswordConfigError> {
        if self.length == 0 {
            return Err(PasswordConfigError::ZeroLength);
        }

        let sets_count = self.include_lowercase as usize
            + self.include_uppercase as usize
            + self.include_digits as usize
            + self.include_symbols as usize;

        if sets_count == 0 {
            return Err(PasswordConfigError::NoCharacterSetsEnabled);
        }

        if self.require_from_each_set && self.length < sets_count {
            return Err(PasswordConfigError::LengthTooShortForSets {
                length: self.length,
                sets_count,
            });
        }

        if self.avoid_ambiguous {
            let available_chars = self.get_available_characters_count();
            if available_chars < self.length {
                return Err(PasswordConfigError::NotEnoughAvailableCharacters {
                    length: self.length,
                    available: available_chars,
                });
            }
        }

        Ok(())
    }
}
