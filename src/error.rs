use std::error::Error;
use std::fmt;
use std::io;

use clap;

#[derive(Debug)]
enum ExtcapErrorKind {
    Io,
    Clap,
    MissingInterface,
    InvalidInterface,
    UnknownStepRequested,
}

#[derive(Debug)]
pub struct ExtcapError {
    kind: ExtcapErrorKind,
    message: String,
}

impl ExtcapError {
    pub(crate) fn missing_interface() -> Self {
        ExtcapError {
            kind: ExtcapErrorKind::MissingInterface,
            message: "Missing interface".to_string(),
        }
    }
    pub(crate) fn invalid_interface(interface: &str) -> Self {
        ExtcapError {
            kind: ExtcapErrorKind::InvalidInterface,
            message: format!("Invalid interface: {}", interface),
        }
    }
    pub(crate) fn unknown_step() -> Self {
        ExtcapError {
            kind: ExtcapErrorKind::UnknownStepRequested,
            message: "Unknown step requested".to_string(),
        }
    }
}

impl Error for ExtcapError {}

impl fmt::Display for ExtcapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<io::Error> for ExtcapError {
    fn from(error: io::Error) -> Self {
        ExtcapError {
            kind: ExtcapErrorKind::Io,
            message: error.to_string(),
        }
    }
}

impl From<clap::Error> for ExtcapError {
    fn from(error: clap::Error) -> Self {
        ExtcapError {
            kind: ExtcapErrorKind::Clap,
            message: error.to_string(),
        }
    }
}
