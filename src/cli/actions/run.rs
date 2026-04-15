use crate::cli::actions::{Action, HashMode};
use crate::pwgen::{
    config::PasswordConfig,
    generate_mnemonic, generate_password,
    hash::{hash_bcrypt, hash_pbkdf2, hash_sha512},
};
use anyhow::{Context, Error, Result};
use crossbeam::channel;
use serde_json::json;
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};
use tokio::task;

type PasswordResult = Result<(String, Option<String>), Error>;
type PasswordEntries = Vec<(String, Option<String>)>;
type CollectedPasswordResults = (PasswordEntries, Option<Error>);

/// Executes the selected generation action and prints its output.
///
/// # Errors
///
/// Returns an error if password or mnemonic generation fails, if hashing fails,
/// or if a background password-generation task terminates unexpectedly.
pub async fn handle(action: Action) -> Result<()> {
    match action {
        Action::GeneratePassword {
            pw_length,
            num_pw,
            pin,
            alphanumeric,
            hash_mode,
            charset,
            json,
        } => {
            let config = if pin {
                PasswordConfig::pin(pw_length)?
            } else if alphanumeric {
                PasswordConfig::alphanumeric(pw_length)?
            } else if let Some(charset) = charset {
                PasswordConfig::custom(pw_length, charset)?
            } else {
                PasswordConfig::new(pw_length)?
            };

            config.validate()?;
            handle_passwords(config, num_pw, hash_mode, json).await
        }
        Action::GenerateMnemonic { word_count, json } => handle_mnemonic_phrase(word_count, json),
    }
}

async fn handle_passwords(
    config: PasswordConfig,
    num_pw: usize,
    hash_mode: HashMode,
    json_output: bool,
) -> Result<()> {
    let (rx, tasks) = spawn_password_workers(&config, num_pw, hash_mode);
    let (json_entries, first_error) = {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        collect_password_results(&rx, json_output, &mut writer)?
    };

    await_password_tasks(tasks).await?;

    if let Some(err) = first_error {
        return Err(err);
    }

    if json_output {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        write_password_json(&mut writer, &json_entries)?;
    }

    Ok(())
}

fn handle_mnemonic_phrase(word_count: usize, json_output: bool) -> Result<()> {
    let mnemonic = generate_mnemonic(word_count)?;

    if json_output {
        let payload = json!([{
            "mnemonic": mnemonic,
            "word_count": word_count,
        }]);
        println!("{payload}");
    } else {
        println!("{mnemonic}");
    }

    Ok(())
}

fn spawn_password_workers(
    config: &PasswordConfig,
    num_pw: usize,
    hash_mode: HashMode,
) -> (channel::Receiver<PasswordResult>, Vec<task::JoinHandle<()>>) {
    let worker_count =
        num_pw.min(thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get));
    let (tx, rx) = channel::bounded::<PasswordResult>(worker_count.saturating_mul(2).max(1));
    let next_job = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let config = config.clone();
        let tx = tx.clone();
        let next_job = Arc::clone(&next_job);

        tasks.push(task::spawn_blocking(move || {
            loop {
                let current_job = next_job.fetch_add(1, Ordering::Relaxed);
                if current_job >= num_pw {
                    break;
                }

                if tx
                    .send(generate_password_entry(&config, hash_mode))
                    .is_err()
                {
                    break;
                }
            }
        }));
    }

    drop(tx);

    (rx, tasks)
}

fn generate_password_entry(
    config: &PasswordConfig,
    hash_mode: HashMode,
) -> Result<(String, Option<String>)> {
    let password = generate_password(config)?;

    let hashed = match hash_mode {
        HashMode::None => None,
        HashMode::Bcrypt => Some(hash_bcrypt(&password)?),
        HashMode::Pbkdf2 => Some(hash_pbkdf2(&password)?),
        HashMode::Sha512 => Some(hash_sha512(&password)?),
    };

    Ok((password, hashed))
}

fn collect_password_results(
    rx: &channel::Receiver<PasswordResult>,
    json_output: bool,
    writer: &mut impl Write,
) -> Result<CollectedPasswordResults> {
    let mut json_entries = Vec::new();
    let mut first_error = None;

    while let Ok(result) = rx.recv() {
        match result {
            Ok((password, hashed)) => {
                if json_output {
                    json_entries.push((password, hashed));
                } else {
                    write_plaintext_entry(writer, &password, hashed.as_deref())?;
                }
            }
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }

    Ok((json_entries, first_error))
}

async fn await_password_tasks(tasks: Vec<task::JoinHandle<()>>) -> Result<()> {
    for task in tasks {
        task.await.context("Password generation task failed")?;
    }

    Ok(())
}

fn write_plaintext_entry(
    writer: &mut impl Write,
    password: &str,
    hash: Option<&str>,
) -> Result<()> {
    if let Some(hash) = hash {
        writeln!(writer, "{password} {hash}")?;
    } else {
        writeln!(writer, "{password}")?;
    }

    Ok(())
}

fn write_password_json(
    writer: &mut impl Write,
    entries: &[(String, Option<String>)],
) -> Result<()> {
    write!(writer, "[")?;

    for (index, (password, hash)) in entries.iter().enumerate() {
        if index > 0 {
            write!(writer, ",")?;
        }

        let json_output = json!({
            "password": password,
            "hash": hash,
        });
        write!(writer, "{json_output}")?;
    }

    writeln!(writer, "]")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow};
    use bip39::{Language, Mnemonic};
    use serde_json::Value;

    #[tokio::test]
    async fn test_handle_password() -> Result<()> {
        let action = Action::GeneratePassword {
            pw_length: 10,
            num_pw: 1,
            pin: false,
            alphanumeric: false,
            hash_mode: HashMode::None,
            charset: None,
            json: false,
        };

        handle(action).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_pin() -> Result<()> {
        let action = Action::GeneratePassword {
            pw_length: 4,
            num_pw: 1,
            pin: true,
            alphanumeric: false,
            hash_mode: HashMode::None,
            charset: None,
            json: false,
        };

        handle(action).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_alphanumeric() -> Result<()> {
        let action = Action::GeneratePassword {
            pw_length: 12,
            num_pw: 1,
            pin: false,
            alphanumeric: true,
            hash_mode: HashMode::None,
            charset: None,
            json: false,
        };

        handle(action).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_invalid_password_action() {
        let action = Action::GeneratePassword {
            pw_length: 0,
            num_pw: 1,
            pin: false,
            alphanumeric: false,
            hash_mode: HashMode::None,
            charset: None,
            json: false,
        };

        assert!(handle(action).await.is_err());
    }

    #[test]
    fn test_handle_mnemonic_phrase() -> Result<()> {
        let phrase = generate_mnemonic(12)?;
        assert_eq!(phrase.split_whitespace().count(), 12);
        assert!(Mnemonic::parse_in_normalized(Language::English, &phrase).is_ok());
        Ok(())
    }

    #[test]
    fn test_handle_mnemonic_json_shape() -> Result<()> {
        let payload = json!([{
            "mnemonic": "alpha beta gamma",
            "word_count": 3,
        }]);
        let parsed: Value = serde_json::from_str(&payload.to_string())?;
        let entry = parsed
            .as_array()
            .and_then(|values| values.first())
            .ok_or_else(|| anyhow!("expected array with one entry"))?;

        assert!(parsed.is_array());
        assert_eq!(entry.get("word_count"), Some(&Value::from(3)));
        Ok(())
    }

    #[test]
    fn test_collect_password_results_json_is_all_or_nothing() -> Result<()> {
        let (tx, rx) = channel::bounded(2);
        let send_ok = tx.send(Ok((String::from("secret"), None)));
        assert!(send_ok.is_ok());
        let send_err = tx.send(Err(anyhow!("boom")));
        assert!(send_err.is_ok());
        drop(tx);

        let mut output = Vec::new();
        let (entries, first_error) = collect_password_results(&rx, true, &mut output)?;
        assert_eq!(entries.len(), 1);
        assert!(first_error.is_some());
        assert!(output.is_empty());
        Ok(())
    }

    #[test]
    fn test_collect_password_results_plaintext_streams_successes() -> Result<()> {
        let (tx, rx) = channel::bounded(2);
        tx.send(Ok((String::from("secret"), Some(String::from("hashed")))))
            .map_err(Error::from)?;
        tx.send(Err(anyhow!("boom"))).map_err(Error::from)?;
        drop(tx);

        let mut output = Vec::new();
        let (entries, first_error) = collect_password_results(&rx, false, &mut output)?;

        assert!(entries.is_empty());
        assert!(first_error.is_some());
        assert_eq!(String::from_utf8(output)?, "secret hashed\n");
        Ok(())
    }
}
