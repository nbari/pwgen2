use anyhow::Result;
use pwgen2::cli::{actions, actions::Action, start};

#[tokio::main]
async fn main() -> Result<()> {
    let action = start()?;

    match action {
        Action::Run { .. } => actions::run::handle(action).await?,
    }

    Ok(())
}
