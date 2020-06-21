// This trait must be implemented so the HTTPd can export metrics
use super::errors::HttpdError;

pub trait Collector {
    fn collect(&self) -> Result<Vec<u8>, HttpdError>;
}
