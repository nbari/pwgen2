pub mod run;

#[derive(Debug)]
pub enum Action {
    Run { pw_length: u8, num_pw: usize },
}
