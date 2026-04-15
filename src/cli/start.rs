use crate::cli::{actions::Action, commands, dispatch::handler};

/// Start the CLI
#[must_use]
pub fn start() -> Action {
    let matches = commands::new().get_matches();
    handler(&matches)
}
