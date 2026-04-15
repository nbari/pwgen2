use pwgen2::cli::{actions, actions::Action, start};

#[tokio::main]
async fn main() {
    let action = start();

    let result = match action {
        Action::GeneratePassword { .. } | Action::GenerateMnemonic { .. } => {
            actions::run::handle(action).await
        }
    };

    if let Err(err) = result {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
