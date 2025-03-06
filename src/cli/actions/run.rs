use crate::cli::actions::Action;
use crate::pwgen::{
    config::PasswordConfig,
    generate_password,
    hash::{hash_bcrypt, hash_pbkdf2, hash_sha512},
};
use anyhow::Result;
use tokio::task;

pub async fn handle(action: Action) -> Result<()> {
    let Action::Run {
        pw_length,
        num_pw,
        pin,
        alphanumeric,
        bcrypt,
        pbkdf2,
        sha512,
        charset,
    } = action;

    let config = if pin {
        PasswordConfig::pin(pw_length)?
    } else if alphanumeric {
        PasswordConfig::alphanumeric(pw_length)?
    } else if let Some(charset) = charset {
        PasswordConfig::custom(pw_length, charset)?
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

                    // Apply hashing if requested
                    if bcrypt {
                        match hash_bcrypt(&password) {
                            Ok(hashed) => println!("{} {}", password, hashed),
                            Err(e) => eprintln!("BCrypt hashing error: {}", e),
                        }
                    } else if pbkdf2 {
                        match hash_pbkdf2(&password) {
                            Ok(hashed) => println!("{} {}", password, hashed),
                            Err(e) => eprintln!("PBKDF2 hashing error: {}", e),
                        }
                    } else if sha512 {
                        match hash_sha512(&password) {
                            Ok(hashed) => println!("{} {}", password, hashed),
                            Err(e) => eprintln!("PBKDF2 hashing error: {}", e),
                        }
                    } else {
                        println!("{}", password);
                    }
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
            bcrypt: false,
            pbkdf2: false,
            sha512: false,
            charset: None,
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
            bcrypt: false,
            pbkdf2: false,
            sha512: false,
            charset: None,
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
            bcrypt: false,
            pbkdf2: false,
            sha512: false,
            charset: None,
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
            bcrypt: false,
            pbkdf2: false,
            sha512: false,
            charset: None,
        };

        let rs = handle(action).await;
        assert!(rs.is_err());
    }
}
