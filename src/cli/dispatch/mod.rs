use crate::cli::actions::Action;
use anyhow::Result;

pub fn handler(matches: &clap::ArgMatches) -> Result<Action> {
    Ok(Action::Run {
        pw_length: matches.get_one::<u8>("length").copied().unwrap_or(18),
        num_pw: matches.get_one::<usize>("number").copied().unwrap_or(1),
        pin: matches.get_flag("pin"),
        alphanumeric: matches.get_flag("alphanumeric"),
        bcrypt: matches.get_flag("bcrypt"),
        pbkdf2: matches.get_flag("pbkdf2"),
        sha512: matches.get_flag("sha512"),
        charset: matches.get_one::<String>("charset").map(|s| s.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::commands::new;

    #[test]
    fn test_handler() -> Result<()> {
        let matches = new().try_get_matches_from(["pwgen2"]);

        assert!(matches.is_ok());

        let m = matches.unwrap();

        assert_eq!(m.get_one::<u8>("length").copied(), Some(18));

        assert_eq!(m.get_one::<usize>("number").copied(), Some(1));

        let action = handler(&m)?;

        match action {
            Action::Run {
                pw_length,
                num_pw,
                pin,
                alphanumeric,
                bcrypt,
                pbkdf2,
                sha512,
                charset,
            } => {
                assert_eq!(pw_length, 18);
                assert_eq!(num_pw, 1);
                assert!(!pin);
                assert!(!alphanumeric);
                assert!(!bcrypt);
                assert!(!pbkdf2);
                assert!(!sha512);
                assert!(charset.is_none());
            }
        }

        Ok(())
    }
}
