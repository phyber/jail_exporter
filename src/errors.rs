//
// jail_exporter
//
// This module implements errors used in the rest of the crate.
//
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
use thiserror::Error;

/// An enum for error types encountered by the jail_exporter.
#[derive(Error, Debug)]
pub enum ExporterError {
    /// Raised when a required argument was not set.
    /// Should not be reachable.
    #[error("{0} was not set.")]
    ArgNotSet(String),

    /// Raised within the `httpd` module if an error is countered while binding
    /// to the given `web.listen-address`.
    #[error("failed to bind to {0}")]
    BindAddress(String),

    /// Raised if an io::Error occurs
    #[error("std::io::Error")]
    IoError(#[from] std::io::Error),

    /// Raised if there are errors originating within the `jail` crate.
    #[error("could not get jail name")]
    JailError(jail::JailError),

    /// Raised if the jail_exporter is not running as root.
    #[error("jail_exporter must be run as root")]
    NotRunningAsRoot,

    /// Raised when issues occur within the file exporter
    #[error("error occurred while persisting metrics")]
    PersistError(#[from] tempfile::PersistError),

    /// Raised if there are errors originating within the `prometheus` crate.
    #[error("error within Prometheus library")]
    PrometheusError(#[from] prometheus::Error),

    /// Raised if there are issues with RACCT/RCTL support.
    #[error("RACCT/RCTL: {0}")]
    RctlUnavailable(String),

    /// Raised if an `askama` template fails to render.
    #[error("Failed to render template")]
    RenderTemplate(#[from] askama::Error),

    /// Raised if there's an issue converting from UTF-8 to String
    #[error("Failed to convert UTF-8 to String")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

// There is no as_dyn_error for jail::JailError, so we manually implement From
impl From<jail::JailError> for ExporterError {
    fn from(e: jail::JailError) -> Self {
        Self::JailError(e)
    }
}
