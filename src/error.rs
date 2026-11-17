use std::fmt;

#[derive(Debug)]
pub enum Error {
    Config(String),
    Saml(String),
    Charon(String),
    Net(String),
    /// A signal (Ctrl-C, SIGTERM, SIGHUP) asked us to disconnect.
    Interrupted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(s) | Error::Saml(s) | Error::Charon(s) | Error::Net(s) => f.write_str(s),
            Error::Interrupted => f.write_str("interrupted"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
