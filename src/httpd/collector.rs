// This trait must be implemented so the HTTPd can export metrics
pub trait Collector {
    fn collect(&self) -> Result<Vec<u8>, Box<dyn ::std::error::Error>>;
}
