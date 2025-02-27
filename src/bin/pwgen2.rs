use anyhow::Result;
use pwgen2::cli::{actions, actions::Action, start};

fn main() -> Result<()> {
    let action = start()?;

    match action {
        Action::Run { .. } => actions::run::handle(action)?,
    }

    Ok(())
}
