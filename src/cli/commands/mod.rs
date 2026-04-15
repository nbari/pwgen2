use clap::{
    Arg, ArgAction, ArgGroup, ColorChoice, Command,
    builder::styling::{AnsiColor, Effects, Styles},
};
use std::env;

fn parse_positive_number(value: &str) -> Result<usize, String> {
    let number: usize = value
        .parse()
        .map_err(|_| "Must be a positive number".to_string())?;

    if number == 0 {
        return Err("Number must be greater than 0".to_string());
    }

    Ok(number)
}

fn parse_mnemonic_word_count(value: &str) -> Result<u8, String> {
    let word_count: u8 = value
        .parse()
        .map_err(|_| "Mnemonic word count must be 12, 15, 18, 21, or 24".to_string())?;

    match word_count {
        12 | 15 | 18 | 21 | 24 => Ok(word_count),
        _ => Err("Mnemonic word count must be 12, 15, 18, 21, or 24".to_string()),
    }
}

fn length_arg() -> Arg {
    Arg::new("length")
        .help("password length")
        .default_value("18")
        .default_value_if("pin", "true", "4")
        .value_parser(clap::value_parser!(u8).range(4..))
        .conflicts_with("mnemonic")
}

fn number_arg() -> Arg {
    Arg::new("number")
        .help("Number of passwords to generate")
        .value_parser(parse_positive_number)
        .default_value("1")
        .conflicts_with("mnemonic")
}

fn pin_arg() -> Arg {
    Arg::new("pin")
        .short('p')
        .long("pin")
        .help("Generate a pin")
        .num_args(0)
        .action(ArgAction::SetTrue)
}

fn alphanumeric_arg() -> Arg {
    Arg::new("alphanumeric")
        .short('a')
        .long("alphanumeric")
        .help("Generate an alphanumeric password")
        .num_args(0)
        .action(ArgAction::SetTrue)
}

fn mnemonic_arg() -> Arg {
    Arg::new("mnemonic")
        .short('m')
        .long("mnemonic")
        .help("Generate an English BIP-39 recovery phrase")
        .long_help(
            "Generate a standard English BIP-39 mnemonic phrase. Omitting the count defaults to 12 words.",
        )
        .value_name("words")
        .num_args(0..=1)
        .default_missing_value("12")
        .value_parser(parse_mnemonic_word_count)
        .conflicts_with_all([
            "pin",
            "alphanumeric",
            "charset",
            "bcrypt",
            "pbkdf2",
            "sha512",
            "length",
            "number",
        ])
}

fn bcrypt_arg() -> Arg {
    Arg::new("bcrypt")
        .short('b')
        .long("bcrypt")
        .help("Hash the generated password using Bcrypt")
        .num_args(0)
        .action(ArgAction::SetTrue)
}

fn pbkdf2_arg() -> Arg {
    Arg::new("pbkdf2")
        .short('k')
        .long("pbkdf2")
        .help("Hash the generated password using PBKDF2")
        .num_args(0)
        .action(ArgAction::SetTrue)
}

fn sha512_arg() -> Arg {
    Arg::new("sha512")
        .short('s')
        .long("sha512")
        .help("Hash the generated password using SHA512")
        .num_args(0)
        .action(ArgAction::SetTrue)
}

fn charset_arg() -> Arg {
    Arg::new("charset")
        .short('c')
        .long("charset")
        .help("Symbols to use for password generation")
        .long_help(
            "Symbols to use for password generation. Passwords keep symbols sparse and never start with a symbol.",
        )
        .value_name("symbols")
        .required(false)
}

fn json_arg() -> Arg {
    Arg::new("json")
        .short('j')
        .long("json")
        .help("Output as JSON")
        .num_args(0)
        .action(ArgAction::SetTrue)
}

pub fn new() -> Command {
    let styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default());

    Command::new("pwgen2")
        .about("password generator")
        .version(env!("CARGO_PKG_VERSION"))
        .color(ColorChoice::Auto)
        .styles(styles)
        .after_help(
            "Notes:\n  Generated passwords keep symbols sparse and never start with a symbol.\n  --mnemonic generates a standard English BIP-39 recovery phrase.",
        )
        .arg(length_arg())
        .arg(number_arg())
        .arg(pin_arg())
        .arg(alphanumeric_arg())
        .arg(mnemonic_arg())
        .arg(bcrypt_arg())
        .arg(pbkdf2_arg())
        .arg(sha512_arg())
        .arg(charset_arg())
        .arg(json_arg())
        .group(
            ArgGroup::new("password-type")
                .args(["pin", "alphanumeric", "charset"])
                .required(false),
        )
        .group(
            ArgGroup::new("hash-type")
                .args(["bcrypt", "pbkdf2", "sha512"])
                .required(false),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_defaults() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2"])?;

        assert_eq!(matches.get_one::<u8>("length").copied(), Some(18));
        assert_eq!(matches.get_one::<usize>("number").copied(), Some(1));
        assert!(!matches.get_flag("pin"));
        assert!(!matches.get_flag("alphanumeric"));
        assert!(matches.get_one::<String>("charset").is_none());
        assert!(matches.get_one::<u8>("mnemonic").is_none());

        Ok(())
    }

    #[test]
    fn test_options_pin() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-p"])?;

        assert_eq!(matches.get_one::<u8>("length").copied(), Some(4));
        assert_eq!(matches.get_one::<usize>("number").copied(), Some(1));
        assert!(matches.get_flag("pin"));
        assert!(!matches.get_flag("alphanumeric"));

        Ok(())
    }

    #[test]
    fn test_options_alphanumeric() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-a"])?;

        assert_eq!(matches.get_one::<u8>("length").copied(), Some(18));
        assert_eq!(matches.get_one::<usize>("number").copied(), Some(1));
        assert!(!matches.get_flag("pin"));
        assert!(matches.get_flag("alphanumeric"));

        Ok(())
    }

    #[test]
    fn test_options_only_pin_or_alphanumeric() {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-a", "-p"]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_options_only_pin_or_charset() {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-a", "-c", "~"]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_options_only_pin_or_alphanumeric_or_charset() {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-a", "-p", "-c", "~"]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_number_of_passwords() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "18", "5"])?;

        assert_eq!(matches.get_one::<u8>("length").copied(), Some(18));
        assert_eq!(matches.get_one::<usize>("number").copied(), Some(5));
        assert!(!matches.get_flag("pin"));
        assert!(!matches.get_flag("alphanumeric"));

        Ok(())
    }

    #[test]
    fn test_password_length() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "32"])?;

        assert_eq!(matches.get_one::<u8>("length").copied(), Some(32));
        assert_eq!(matches.get_one::<usize>("number").copied(), Some(1));
        assert!(!matches.get_flag("pin"));
        assert!(!matches.get_flag("alphanumeric"));

        Ok(())
    }

    #[test]
    fn test_options_only_b_or_k() {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-b", "-k", "s"]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_charset() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-c", "~"])?;

        assert_eq!(matches.get_one::<u8>("length").copied(), Some(18));
        assert_eq!(matches.get_one::<usize>("number").copied(), Some(1));
        assert!(!matches.get_flag("pin"));
        assert!(!matches.get_flag("alphanumeric"));
        assert_eq!(
            matches.get_one::<String>("charset").cloned(),
            Some(String::from("~"))
        );

        Ok(())
    }

    #[test]
    fn test_mnemonic_defaults_to_twelve_words() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-m"])?;
        assert_eq!(matches.get_one::<u8>("mnemonic").copied(), Some(12));
        Ok(())
    }

    #[test]
    fn test_mnemonic_accepts_24_words() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-m", "24"])?;
        assert_eq!(matches.get_one::<u8>("mnemonic").copied(), Some(24));
        Ok(())
    }

    #[test]
    fn test_mnemonic_rejects_invalid_word_count() {
        let matches = new().try_get_matches_from(vec!["pwgen2", "--mnemonic", "14"]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_mnemonic_conflicts_with_positionals() {
        let matches = new().try_get_matches_from(vec!["pwgen2", "--mnemonic", "24", "3"]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_mnemonic_conflicts_with_password_modes() {
        let matches = new().try_get_matches_from(vec!["pwgen2", "--mnemonic", "-p"]);
        assert!(matches.is_err());
    }
}
