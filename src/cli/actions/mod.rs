pub mod run;

#[derive(Debug)]
pub enum Action {
    Run {
        pw_length: u8,
        num_pw: usize,
        pin: bool,
        alphanumeric: bool,
        bcrypt: bool,
        pbkdf2: bool,
        sha512: bool,
        charset: Option<String>,
    },
}
