use crate::cli::actions::Action;
use crate::pwgen::{
    config::PasswordConfig,
    generate_password,
    hash::{hash_bcrypt, hash_pbkdf2, hash_sha512},
};
use anyhow::{Error, Result};
use crossbeam::channel;
use serde_json::json;
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
        json, // Check for JSON flag
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
            //
            if json {
                print!("[");
                if num_pw == 0 {
                    print!("]");
                }
            }

            // Create a crossbeam channel
            let (tx, rx) = channel::bounded::<Result<(String, Option<String>), Error>>(32);

            for _ in 0..num_pw {
                let config = config.clone();
                let tx = tx.clone();

                task::spawn_blocking(move || {
                    let result = {
                        let password = generate_password(&config);

                        // Apply hashing if requested
                        let hashed = if bcrypt {
                            hash_bcrypt(&password).ok()
                        } else if pbkdf2 {
                            hash_pbkdf2(&password).ok()
                        } else if sha512 {
                            hash_sha512(&password).ok()
                        } else {
                            None
                        };

                        Ok((password, hashed))
                    };

                    let _ = tx.send(result);
                });
            }

            // Drop the sender to signal that no more messages will be sent
            drop(tx);

            // Track number of items processed for JSON formatting
            let mut processed = 0;

            // Process results as they arrive
            while let Ok(result) = rx.recv() {
                match result {
                    Ok((password, hashed)) => {
                        if json {
                            if processed > 0 {
                                print!(",");
                            }
                            let json_output = json!({
                                "password": password,
                                "hash": hashed
                            });
                            print!("{}", json_output);
                            processed += 1;

                            // If this is the last item, print the closing bracket
                            if processed == num_pw {
                                println!("]");
                            }
                        } else if let Some(hash) = hashed {
                            println!("{} {}", password, hash);
                        } else {
                            println!("{}", password);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error generating password: {}", e);
                    }
                }
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
            json: false,
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
            json: false,
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
            json: false,
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
            json: false,
        };

        let rs = handle(action).await;
        assert!(rs.is_err());
    }
}
