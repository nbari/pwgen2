use anyhow::{Result, anyhow};
use assert_cmd::Command;
use bip39::{Language, Mnemonic};
use predicates::prelude::*;
use serde_json::Value;

fn cargo_cmd() -> Result<Command> {
    Command::cargo_bin(env!("CARGO_PKG_NAME")).map_err(Into::into)
}

fn first_array_entry(value: &Value) -> Result<&Value> {
    value
        .as_array()
        .and_then(|entries| entries.first())
        .ok_or_else(|| anyhow!("expected a non-empty JSON array"))
}

#[test]
fn test_help() -> Result<()> {
    let mut cmd = cargo_cmd()?;
    cmd.arg("--help")
        .assert()
        .stdout(predicate::str::contains("password generator"))
        .stdout(predicate::str::contains("-m, --mnemonic [<words>]"));
    Ok(())
}

#[test]
fn test_create_password() -> Result<()> {
    for _ in 0..100 {
        let mut cmd = cargo_cmd()?;
        cmd.assert()
            .stdout(predicate::function(|s: &str| s.trim().len() == 18));
    }
    Ok(())
}

#[test]
fn test_create_password_json_output() -> Result<()> {
    let mut cmd = cargo_cmd()?;
    let output = cmd
        .arg("-j")
        .arg("18")
        .arg("3")
        .assert()
        .get_output()
        .stdout
        .clone();
    let parsed: Value = serde_json::from_slice(&output)?;
    let first = first_array_entry(&parsed)?;

    assert_eq!(parsed.as_array().map(Vec::len), Some(3));
    assert!(first.get("password").is_some_and(Value::is_string));
    assert!(first.get("hash").is_some_and(Value::is_null));
    Ok(())
}

#[test]
fn test_create_pin() -> Result<()> {
    let mut cmd = cargo_cmd()?;
    let pin_pattern = predicate::str::is_match(r"\d{4}\n")?;
    cmd.arg("-p").assert().stdout(pin_pattern);
    Ok(())
}

#[test]
fn test_create_alphanumeric() -> Result<()> {
    let pattern = predicate::str::is_match(r"^[a-zA-Z0-9]{18}\n$")?;

    for _ in 0..100 {
        let mut cmd = cargo_cmd()?;
        cmd.arg("-a").assert().stdout(pattern.clone());
    }
    Ok(())
}

#[test]
fn test_multibyte_custom_symbol_does_not_panic() -> Result<()> {
    let mut cmd = cargo_cmd()?;
    cmd.arg("-c")
        .arg("€")
        .arg("12")
        .arg("3")
        .assert()
        .success()
        .stdout(predicate::str::contains("€"));
    Ok(())
}

#[test]
fn test_create_mnemonic_defaults_to_twelve_words() -> Result<()> {
    let mut cmd = cargo_cmd()?;
    let output = cmd.arg("-m").assert().get_output().stdout.clone();
    let phrase = String::from_utf8(output)?;
    let phrase = phrase.trim();

    assert_eq!(phrase.split_whitespace().count(), 12);
    assert!(Mnemonic::parse_in_normalized(Language::English, phrase).is_ok());
    Ok(())
}

#[test]
fn test_create_mnemonic_with_24_words() -> Result<()> {
    let mut cmd = cargo_cmd()?;
    let output = cmd.arg("-m").arg("24").assert().get_output().stdout.clone();
    let phrase = String::from_utf8(output)?;
    let phrase = phrase.trim();

    assert_eq!(phrase.split_whitespace().count(), 24);
    assert!(Mnemonic::parse_in_normalized(Language::English, phrase).is_ok());
    Ok(())
}

#[test]
fn test_create_mnemonic_json_output() -> Result<()> {
    let mut cmd = cargo_cmd()?;
    let output = cmd.arg("-m").arg("-j").assert().get_output().stdout.clone();
    let parsed: Value = serde_json::from_slice(&output)?;
    let first = first_array_entry(&parsed)?;
    let phrase = first
        .get("mnemonic")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("expected mnemonic string"))?;

    assert_eq!(first.get("word_count"), Some(&Value::from(12)));
    assert_eq!(phrase.split_whitespace().count(), 12);
    assert!(Mnemonic::parse_in_normalized(Language::English, phrase).is_ok());
    Ok(())
}

#[test]
fn test_mnemonic_conflicts_with_password_length() -> Result<()> {
    let mut cmd = cargo_cmd()?;
    cmd.arg("-m")
        .arg("24")
        .arg("18")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
    Ok(())
}

#[test]
fn test_mnemonic_rejects_invalid_word_count() -> Result<()> {
    let mut cmd = cargo_cmd()?;
    cmd.arg("-m")
        .arg("14")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Mnemonic word count must be 12, 15, 18, 21, or 24",
        ));
    Ok(())
}
