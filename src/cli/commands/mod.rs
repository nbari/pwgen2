use clap::{
    builder::styling::{AnsiColor, Effects, Styles},
    Arg, ColorChoice, Command,
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
            Arg::new("pw_length")
                .help("password length")
                .default_value("18")
                .value_parser(clap::value_parser!(u8).range(4..))
                .value_name("NUMBER"),
        )
        .arg(
            Arg::new("num_pw")
                .help("Number of passwords to generate")
                .value_parser(clap::value_parser!(usize))
                .default_value("1")
                .value_name("NUMBER"),
        )
}
