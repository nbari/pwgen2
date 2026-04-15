use crate::cli::actions::{Action, HashMode};

pub fn handler(matches: &clap::ArgMatches) -> Action {
    if let Some(word_count) = matches.get_one::<u8>("mnemonic").copied() {
        return Action::GenerateMnemonic {
            word_count: usize::from(word_count),
            json: matches.get_flag("json"),
        };
    }

    Action::GeneratePassword {
        pw_length: matches.get_one::<u8>("length").copied().unwrap_or(18),
        num_pw: matches.get_one::<usize>("number").copied().unwrap_or(1),
        pin: matches.get_flag("pin"),
        alphanumeric: matches.get_flag("alphanumeric"),
        hash_mode: if matches.get_flag("bcrypt") {
            HashMode::Bcrypt
        } else if matches.get_flag("pbkdf2") {
            HashMode::Pbkdf2
        } else if matches.get_flag("sha512") {
            HashMode::Sha512
        } else {
            HashMode::None
        },
        charset: matches.get_one::<String>("charset").cloned(),
        json: matches.get_flag("json"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::commands::new;
    use anyhow::Result;

    #[test]
    fn test_handler() -> Result<()> {
        let m = new().try_get_matches_from(["pwgen2"])?;

        assert_eq!(m.get_one::<u8>("length").copied(), Some(18));
        assert_eq!(m.get_one::<usize>("number").copied(), Some(1));

        let action = handler(&m);
        assert!(matches!(action, Action::GeneratePassword { .. }));

        if let Action::GeneratePassword {
            pw_length,
            num_pw,
            pin,
            alphanumeric,
            hash_mode,
            charset,
            json,
        } = action
        {
            assert_eq!(pw_length, 18);
            assert_eq!(num_pw, 1);
            assert!(!pin);
            assert!(!alphanumeric);
            assert_eq!(hash_mode, HashMode::None);
            assert!(charset.is_none());
            assert!(!json);
        }
        Ok(())
    }

    #[test]
    fn test_handler_for_mnemonic() -> Result<()> {
        let m = new().try_get_matches_from(["pwgen2", "--mnemonic"])?;
        let action = handler(&m);
        assert!(matches!(action, Action::GenerateMnemonic { .. }));

        if let Action::GenerateMnemonic { word_count, json } = action {
            assert_eq!(word_count, 12);
            assert!(!json);
        }
        Ok(())
    }
}
