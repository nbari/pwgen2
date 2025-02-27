use crate::cli::actions::Action;
use crate::pwgen::{config::PasswordConfig, generate_password};
use anyhow::Result;
use tokio::task;

pub async fn handle(action: Action) -> Result<()> {
    let Action::Run { pw_length, num_pw } = action;

    let config = PasswordConfig::new(pw_length)?;

    match config.validate() {
        Ok(()) => {
            let mut handles = Vec::new();

            for _ in 0..num_pw {
                let config = config.clone();

                let handle = task::spawn_blocking(move || {
                    let password = generate_password(&config);
                    println!("{}", password);
                });

                handles.push(handle);
            }

            // Await all spawned tasks
            for handle in handles {
                handle.await.unwrap(); // Handle errors properly in production
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
