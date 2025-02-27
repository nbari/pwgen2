use crate::cli::actions::Action;
use crate::pwgen::{config::PasswordConfig, generate_password};
use anyhow::Result;

pub fn handle(action: Action) -> Result<()> {
    let Action::Run {
        pw_length,
        num_pw: _,
    } = action;

    let config = PasswordConfig {
        length: pw_length,
        include_lowercase: true,
        include_uppercase: true,
        include_digits: true,
        include_symbols: true,
        avoid_ambiguous: true,
        require_from_each_set: true,
    };

    match config.validate() {
        Ok(()) => {
            let password = generate_password(&config);
            println!("{}", password);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
