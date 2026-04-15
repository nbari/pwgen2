use crate::pwgen::{AMBIGUOUS_CHARS, DEFAULT_CHARSETS};

/// Error type for password configuration validation.
#[derive(Debug)]
pub enum PasswordConfigError {
    ZeroLength,
    NoCharacterSetsEnabled,
    LengthTooShortForSets { length: u8, sets_count: u8 },
    PinLengthTooShort,
    EmptyCustomCharset,
    MissingNonSymbolCharacters,
    EmptyCharacterPool(&'static str),
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
                    "Password length ({length}) must be at least equal to the number of required character sets ({sets_count}).",
                )
            }
            Self::PinLengthTooShort => write!(f, "PIN length must be at least 4 characters."),
            Self::EmptyCustomCharset => {
                write!(
                    f,
                    "Custom symbol charset must contain at least one character."
                )
            }
            Self::MissingNonSymbolCharacters => write!(
                f,
                "At least one non-symbol character set must be included when symbols are enabled.",
            ),
            Self::EmptyCharacterPool(pool_name) => {
                write!(
                    f,
                    "Character pool '{pool_name}' must contain at least one character."
                )
            }
        }
    }
}

impl std::error::Error for PasswordConfigError {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CharacterSetSelection {
    Include,
    Exclude,
}

impl CharacterSetSelection {
    const fn is_enabled(self) -> bool {
        matches!(self, Self::Include)
    }
}

impl From<bool> for CharacterSetSelection {
    fn from(value: bool) -> Self {
        if value { Self::Include } else { Self::Exclude }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AmbiguousCharacterPolicy {
    Avoid,
    Allow,
}

impl AmbiguousCharacterPolicy {
    const fn avoids_ambiguous(self) -> bool {
        matches!(self, Self::Avoid)
    }
}

impl From<bool> for AmbiguousCharacterPolicy {
    fn from(value: bool) -> Self {
        if value { Self::Avoid } else { Self::Allow }
    }
}

/// Configuration for password generation.
#[derive(Debug, Clone)]
pub struct PasswordConfig {
    /// Length of the password to generate.
    pub length: u8,

    /// Optional custom symbol set for password generation.
    pub charset: Option<String>,

    /// Include lowercase letters (a-z).
    pub include_lowercase: CharacterSetSelection,

    /// Include uppercase letters (A-Z).
    pub include_uppercase: CharacterSetSelection,

    /// Include numeric digits (0-9).
    pub include_digits: CharacterSetSelection,

    /// Include special symbols.
    pub include_symbols: CharacterSetSelection,

    /// Whether to avoid ambiguous characters such as `0O1Il5S`.
    pub avoid_ambiguous: AmbiguousCharacterPolicy,
}

#[derive(Debug, Clone)]
pub(crate) struct CharacterPools {
    pub lowercase: Vec<char>,
    pub uppercase: Vec<char>,
    pub digits: Vec<char>,
    pub symbols: Vec<char>,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            length: 18,
            charset: None,
            include_lowercase: CharacterSetSelection::Include,
            include_uppercase: CharacterSetSelection::Include,
            include_digits: CharacterSetSelection::Include,
            include_symbols: CharacterSetSelection::Include,
            avoid_ambiguous: AmbiguousCharacterPolicy::Avoid,
        }
    }
}

impl PasswordConfig {
    /// Creates a new password configuration with the specified length.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordConfigError::ZeroLength`] when `length` is 0.
    pub fn new(length: u8) -> Result<Self, PasswordConfigError> {
        if length == 0 {
            return Err(PasswordConfigError::ZeroLength);
        }

        Ok(Self {
            length,
            ..Self::default()
        })
    }

    /// Creates a new password configuration for a PIN.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordConfigError::PinLengthTooShort`] when `length` is less than 4.
    pub const fn pin(length: u8) -> Result<Self, PasswordConfigError> {
        if length < 4 {
            return Err(PasswordConfigError::PinLengthTooShort);
        }

        Ok(Self {
            length,
            charset: None,
            include_lowercase: CharacterSetSelection::Exclude,
            include_uppercase: CharacterSetSelection::Exclude,
            include_digits: CharacterSetSelection::Include,
            include_symbols: CharacterSetSelection::Exclude,
            avoid_ambiguous: AmbiguousCharacterPolicy::Allow,
        })
    }

    /// Creates an alphanumeric password configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordConfigError::ZeroLength`] when `length` is 0.
    pub fn alphanumeric(length: u8) -> Result<Self, PasswordConfigError> {
        Self::new(length).map(|config| config.with_symbols(false))
    }

    /// Creates a password configuration with a custom symbol set.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordConfigError::ZeroLength`] when `length` is 0.
    pub fn custom(length: u8, charset: String) -> Result<Self, PasswordConfigError> {
        Self::new(length).map(|config| Self {
            charset: Some(charset),
            ..config
        })
    }

    #[must_use]
    pub fn with_lowercase(mut self, include: bool) -> Self {
        self.include_lowercase = CharacterSetSelection::from(include);
        self
    }

    #[must_use]
    pub fn with_uppercase(mut self, include: bool) -> Self {
        self.include_uppercase = CharacterSetSelection::from(include);
        self
    }

    #[must_use]
    pub fn with_digits(mut self, include: bool) -> Self {
        self.include_digits = CharacterSetSelection::from(include);
        self
    }

    #[must_use]
    pub fn with_symbols(mut self, include: bool) -> Self {
        self.include_symbols = CharacterSetSelection::from(include);
        self
    }

    #[must_use]
    pub fn with_avoid_ambiguous(mut self, avoid: bool) -> Self {
        self.avoid_ambiguous = AmbiguousCharacterPolicy::from(avoid);
        self
    }

    pub(crate) fn character_pools(&self) -> Result<CharacterPools, PasswordConfigError> {
        if self.length == 0 {
            return Err(PasswordConfigError::ZeroLength);
        }

        let sets_count = u8::from(self.include_lowercase.is_enabled())
            + u8::from(self.include_uppercase.is_enabled())
            + u8::from(self.include_digits.is_enabled())
            + u8::from(self.include_symbols.is_enabled());

        if sets_count == 0 {
            return Err(PasswordConfigError::NoCharacterSetsEnabled);
        }

        if self.length < sets_count {
            return Err(PasswordConfigError::LengthTooShortForSets {
                length: self.length,
                sets_count,
            });
        }

        let avoid_ambiguous = self.avoid_ambiguous.avoids_ambiguous();

        let lowercase = if self.include_lowercase.is_enabled() {
            DEFAULT_CHARSETS
                .lowercase
                .chars()
                .filter(|c| !avoid_ambiguous || !AMBIGUOUS_CHARS.contains(*c))
                .collect()
        } else {
            Vec::new()
        };

        let uppercase = if self.include_uppercase.is_enabled() {
            DEFAULT_CHARSETS
                .uppercase
                .chars()
                .filter(|c| !avoid_ambiguous || !AMBIGUOUS_CHARS.contains(*c))
                .collect()
        } else {
            Vec::new()
        };

        let digits = if self.include_digits.is_enabled() {
            DEFAULT_CHARSETS
                .digits
                .chars()
                .filter(|c| !avoid_ambiguous || !AMBIGUOUS_CHARS.contains(*c))
                .collect()
        } else {
            Vec::new()
        };

        let symbols = if self.include_symbols.is_enabled() {
            let source = self.charset.as_deref().unwrap_or(DEFAULT_CHARSETS.symbols);
            if source.is_empty() {
                return Err(PasswordConfigError::EmptyCustomCharset);
            }
            source.chars().collect()
        } else {
            Vec::new()
        };

        if self.include_symbols.is_enabled()
            && lowercase.is_empty()
            && uppercase.is_empty()
            && digits.is_empty()
        {
            return Err(PasswordConfigError::MissingNonSymbolCharacters);
        }

        Ok(CharacterPools {
            lowercase,
            uppercase,
            digits,
            symbols,
        })
    }

    /// Validates the configuration before password generation.
    ///
    /// # Errors
    ///
    /// Returns a [`PasswordConfigError`] when the configuration cannot produce
    /// a password that satisfies the current generator rules.
    pub fn validate(&self) -> Result<(), PasswordConfigError> {
        self.character_pools()?;
        Ok(())
    }
}
