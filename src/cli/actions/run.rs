use crate::cli::actions::Action;
use crate::pwgen::{config::PasswordConfig, generate_password};
use anyhow::Result;
use tokio::task;

pub async fn handle(action: Action) -> Result<()> {
    let Action::Run {
        pw_length,
        num_pw,
        pin,
        alphanumeric,
    } = action;

    let config = if pin {
        PasswordConfig::pin(pw_length)?
    } else if alphanumeric {
        PasswordConfig::alphanumeric(pw_length)?
    } else {
        PasswordConfig::new(pw_length)?
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::actions::Action;

    #[tokio::test]
    async fn test_handle() {
        let action = Action::Run {
            pw_length: 10,
            num_pw: 1,
            pin: false,
            alphanumeric: false,
        };

        let rs = handle(action).await;
        assert!(rs.is_ok());
    }

    #[tokio::test]
    async fn test_handle_pin() {
        let action = Action::Run {
            pw_length: 4,
            num_pw: 1,
            pin: true,
            alphanumeric: false,
        };

        let rs = handle(action).await;
        assert!(rs.is_ok());
    }

    #[tokio::test]
    async fn test_handle_alphanumeric() {
        let action = Action::Run {
            pw_length: 4,
            num_pw: 1,
            pin: false,
            alphanumeric: true,
        };

        let rs = handle(action).await;
        assert!(rs.is_ok());
    }

    #[tokio::test]
    async fn test_handle_invalid() {
        let action = Action::Run {
            pw_length: 0,
            num_pw: 1,
            pin: false,
            alphanumeric: false,
        };

        let rs = handle(action).await;
        assert!(rs.is_err());
    }
}
