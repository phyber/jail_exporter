//
// jail_exporter
//
// This module implements errors used in the rest of the crate.
//
#![forbid(unsafe_code)]
use failure::Fail;
use std::fmt;

/// An enum for error types encountered by the jail_exporter.
///
/// Implements the `Fail` trait of the `failure` crate.
#[derive(Fail)]
pub enum Error {
    /// Raised when a required argument was not set.
    /// Should not be reachable.
    #[fail(display = "{} was not set.", _0)]
    ArgNotSet(String),

    /// Raised within the `httpd` module if an error is countered while binding
    /// to the given `web.listen-address`.
    #[fail(display = "failed to bind to {}", _0)]
    BindAddress(String),

    /// Raised if an io::Error occurs
    #[fail(display = "std::io::Error")]
    IoError(#[fail(cause)] std::io::Error),

    /// Raised if there are errors originating within the `jail` crate.
    #[fail(display = "could not get jail name")]
    JailError(#[fail(cause)] jail::JailError),

    /// Raised if the jail_exporter is not running as root.
    #[fail(display = "jail_exporter must be run as root")]
    NotRunningAsRoot,

    /// Raised when issues occur within the file exporter
    #[fail(display = "error occurred while persisting metrics")]
    PersistError(#[fail(cause)] tempfile::PersistError),

    /// Raised if there are errors originating within the `prometheus` crate.
    #[fail(display = "error within Prometheus library")]
    PrometheusError(#[fail(cause)] prometheus::Error),

    /// Raised if there are issues with RACCT/RCTL support.
    #[fail(display = "RACCT/RCTL: {}", _0)]
    RctlUnavailable(String),

    /// Raised if an `askama` template fails to render.
    #[fail(display = "Failed to render template: {}", _0)]
    RenderTemplate(String),

    /// Raised if there's an issue converting from UTF-8 to String
    #[fail(display = "Failed to convert UTF-8 to String")]
    Utf8Error(#[fail(cause)] std::string::FromUtf8Error),
}

// Implements basic output, allowing the above display strings to be used when
// main exits due to an Error.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<jail::JailError> for Error {
    fn from(e: jail::JailError) -> Self {
        Error::JailError(e)
    }
}

impl From<prometheus::Error> for Error {
    fn from(e: prometheus::Error) -> Self {
        Error::PrometheusError(e)
    }
}

impl From<tempfile::PersistError> for Error {
    fn from(e: tempfile::PersistError) -> Self {
        Error::PersistError(e)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::Utf8Error(e)
    }
}
