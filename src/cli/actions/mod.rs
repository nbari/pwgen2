pub mod run;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HashMode {
    None,
    Bcrypt,
    Pbkdf2,
    Sha512,
}

#[derive(Debug)]
pub enum Action {
    GeneratePassword {
        pw_length: u8,
        num_pw: usize,
        pin: bool,
        alphanumeric: bool,
        hash_mode: HashMode,
        charset: Option<String>,
        json: bool,
    },
    GenerateMnemonic {
        word_count: usize,
        json: bool,
    },
}
