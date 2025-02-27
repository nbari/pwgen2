pub mod run;

#[derive(Debug)]
pub enum Action {
    Run { pw_length: usize, num_pw: usize },
}
