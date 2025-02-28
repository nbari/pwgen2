/// Error type for password configuration validation
#[derive(Debug)]
pub enum PasswordConfigError {
    ZeroLength,
    NoCharacterSetsEnabled,
    LengthTooShortForSets { length: u8, sets_count: u8 },
    NotEnoughAvailableCharacters { length: u8, available: u8 },
    PinLengthTooShort,
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
            Self::PinLengthTooShort => write!(f, "PIN length must be at least 4 characters."),
        }
    }
}

impl std::error::Error for PasswordConfigError {}

/// Configuration for password generation
#[derive(Debug, Clone)]
pub struct PasswordConfig {
    /// Length of the password to generate
    pub length: u8,

    /// Include lowercase letters (a-z)
    pub include_lowercase: bool,

    /// Include uppercase letters (A-Z)
    pub include_uppercase: bool,

    /// Include numeric digits (0-9)
    pub include_digits: bool,

    /// Include special symbols
    pub include_symbols: bool,

    /// Avoid ambiguous characters (0O1Il5S)
    pub avoid_ambiguous: bool,
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
        }
    }
}

impl PasswordConfig {
    /// Creates a new password configuration with the specified length
    /// and default settings for other options
    pub fn new(length: u8) -> Result<Self, PasswordConfigError> {
        if length == 0 {
            return Err(PasswordConfigError::ZeroLength);
        }

        Ok(Self {
            length,
            ..Self::default()
        })
    }

    /// Creates a new password configuration for a PIN
    pub const fn pin(length: u8) -> Result<Self, PasswordConfigError> {
        if length < 4 {
            return Err(PasswordConfigError::PinLengthTooShort);
        }

        Ok(Self {
            length,
            include_lowercase: false,
            include_uppercase: false,
            include_digits: true,
            include_symbols: false,
            avoid_ambiguous: false,
        })
    }

    /// Creates an alphanumeric password configuration
    pub const fn alphanumeric(length: u8) -> Result<Self, PasswordConfigError> {
        Ok(Self {
            length,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: false,
            avoid_ambiguous: true,
        })
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

    /// Validates the configuration
    pub const fn validate(&self) -> Result<(), PasswordConfigError> {
        if self.length == 0 {
            return Err(PasswordConfigError::ZeroLength);
        }

        let sets_count = self.include_lowercase as u8
            + self.include_uppercase as u8
            + self.include_digits as u8
            + self.include_symbols as u8;

        if sets_count == 0 {
            return Err(PasswordConfigError::NoCharacterSetsEnabled);
        }

        if self.length < sets_count {
            return Err(PasswordConfigError::LengthTooShortForSets {
                length: self.length,
                sets_count,
            });
        }

        Ok(())
    }
}
