//
// jail_exporter
//
// An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//
#![forbid(unsafe_code)]
use failure::Fail;
use std::fmt;

#[derive(Fail)]
pub enum Error {
    #[fail(display = "{} was not parsable.", _0)]
    ArgNotParsable(String),

    #[fail(display = "{} was not set.", _0)]
    ArgNotSet(String),

    #[fail(display = "failed to bind to '{}'", _0)]
    BindAddress(String),

    #[fail(display = "jail_exporter must be run as root")]
    NotRunningAsRoot,

    #[fail(display = "{}", _0)]
    RctlUnavailable(String),

    #[fail(display = "Failed to render template: {}", _0)]
    RenderTemplate(String),
}

// Implements basic output, allowing the above display strings to be used when
// main exits due to an Error.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
