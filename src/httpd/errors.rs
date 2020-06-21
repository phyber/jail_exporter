// httpd errors
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpdError {
    /// Returned when Httpd cannot bind to the given address.
    #[error("failed to bind to {0}")]
    BindAddress(String),

    /// Returned by the Collector::collect trait method when there are issues.
    #[error("error collecting metrics: {0}")]
    CollectorError(String),

    /// Returned when there are issues running the Httpd.
    #[error("std::io::Error")]
    IoError(#[from] std::io::Error),

    /// Returned when there are issues rendering the index template.
    #[error("failed to render template")]
    RenderTemplate(#[from] askama::Error),
}
