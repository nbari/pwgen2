use clap::{
    builder::styling::{AnsiColor, Effects, Styles},
    Arg, ArgAction, ArgGroup, ColorChoice, Command,
};
use std::env;

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
        .arg(
            Arg::new("length")
                .help("password length")
                .default_value("18")
                .default_value_if("pin", "true", "4")
                .value_parser(clap::value_parser!(u8).range(4..)),
        )
        .arg(
            Arg::new("number")
                .help("Number of passwords to generate")
                .value_parser(|s: &str| {
                    let n: usize = s.parse().map_err(|_| "Must be a positive number")?;
                    if n == 0 {
                        Err("Number must be greater than 0".to_string())
                    } else {
                        Ok(n)
                    }
                })
                .default_value("1"),
        )
        .arg(
            Arg::new("pin")
                .short('p')
                .long("pin")
                .help("Generate a pin")
                .num_args(0)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("alphanumeric")
                .short('a')
                .long("alphanumeric")
                .help("Generate an alphanumeric password")
                .num_args(0)
                .action(ArgAction::SetTrue),
        )
        .group(
            ArgGroup::new("password-type")
                .args(["pin", "alphanumeric"])
                .required(false),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use assert_cmd::Command;
    use predicates::prelude::*;

    #[test]
    fn test_help() {
        let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
        let assert = cmd.arg("--help").assert();

        assert.stdout(predicate::str::contains("password generator"));
    }

    #[test]
    fn test_create_password() {
        for _ in 0..100 {
            let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
            let assert = cmd.assert();

            assert.stdout(predicate::function(|s: &str| s.trim().len() == 18));
        }
    }

    #[test]
    fn test_create_pin() {
        let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
        let assert = cmd.arg("-p").assert();

        assert.stdout(predicate::str::is_match(r"\d{4}\n").unwrap());
    }

    #[test]
    fn test_create_alphanumeric() {
        let pattern = r"^[a-zA-Z0-9]{18}\n$"; // Ensure exactly 18 alphanumeric chars + newline

        for _ in 0..100 {
            let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
            cmd.arg("-a")
                .assert()
                .stdout(predicate::str::is_match(pattern).unwrap());
        }
    }

    #[test]
    fn test_defaults() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2"]);

        assert!(matches.is_ok());

        let m = matches?;

        assert_eq!(m.get_one::<u8>("length").copied(), Some(18));
        assert_eq!(m.get_one::<usize>("number").copied(), Some(1));
        assert!(!m.get_flag("pin"));
        assert!(!m.get_flag("alphanumeric"));

        Ok(())
    }

    #[test]
    fn test_options_pin() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-p"]);

        assert!(matches.is_ok());

        let m = matches?;

        assert_eq!(m.get_one::<u8>("length").copied(), Some(4));
        assert_eq!(m.get_one::<usize>("number").copied(), Some(1));
        assert!(m.get_flag("pin"));
        assert!(!m.get_flag("alphanumeric"));

        Ok(())
    }

    #[test]
    fn test_options_alphanumeric() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-a"]);

        assert!(matches.is_ok());

        let m = matches?;

        assert_eq!(m.get_one::<u8>("length").copied(), Some(18));
        assert_eq!(m.get_one::<usize>("number").copied(), Some(1));
        assert!(!m.get_flag("pin"));
        assert!(m.get_flag("alphanumeric"));

        Ok(())
    }

    #[test]
    fn test_options_only_pin_or_alphanumeric() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "-a", "-p"]);

        assert!(matches.is_err());

        Ok(())
    }

    #[test]
    fn test_number_of_passwords() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "18", "5"]);

        assert!(matches.is_ok());

        let m = matches?;

        assert_eq!(m.get_one::<u8>("length").copied(), Some(18));
        assert_eq!(m.get_one::<usize>("number").copied(), Some(5));
        assert!(!m.get_flag("pin"));
        assert!(!m.get_flag("alphanumeric"));

        Ok(())
    }

    #[test]
    fn test_password_length() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2", "32"]);

        assert!(matches.is_ok());

        let m = matches?;

        assert_eq!(m.get_one::<u8>("length").copied(), Some(32));
        assert_eq!(m.get_one::<usize>("number").copied(), Some(1));
        assert!(!m.get_flag("pin"));
        assert!(!m.get_flag("alphanumeric"));

        Ok(())
    }
}
