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

    #[test]
    fn test_new() -> Result<()> {
        let matches = new().try_get_matches_from(vec!["pwgen2"]);

        assert!(matches.is_ok());

        Ok(())
    }
}
