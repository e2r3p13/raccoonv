use std::error::Error;
use std::fmt;

#[derive (Debug)]
pub struct RVError {
    pub msg: String
}

impl Error for RVError { }

impl fmt::Display for RVError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error: {}", &self.msg)
    }
}

