// File exporter
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
use crate::errors::ExporterError;
use crate::exporter::Exporter;
use log::debug;
use std::io::{
    self,
    Write,
};
use std::path::{
    Path,
    PathBuf,
};
use tempfile::NamedTempFile;

enum Output {
    File(PathBuf),
    Stdout,
}

pub struct FileExporter {
    dest: Output,
}

impl FileExporter {
    pub fn new(path: &str) -> Self {
        // "-" is a special case and has us write to stdout.
        let output = if path == "-" {
            debug!("New FileExporter outputting to stdout");

            Output::Stdout
        }
        else {
            debug!("New FileExporter outputting to {}", path);

            let path = Path::new(&path);
            Output::File(path.into())
        };

        Self {
            dest: output,
        }
    }

    // Handles choosing the correct output type based on path
    fn write(&self, metrics: Vec<u8>) -> Result<(), ExporterError> {
        match &self.dest {
            Output::Stdout => {
                debug!("Writing metrics to stdout");

                io::stdout().write_all(&metrics)?;
            },
            Output::File(path) => {
                debug!("Writing metrics to {:?}", path);

                // We already vetted the parent in the CLI validator, so unwrap
                // here should be fine.
                let parent = path.parent().unwrap();

                // We do this since we need the temporary file to be on the
                // same filesystem as the final persisted file.
                let mut file = NamedTempFile::new_in(&parent)?;
                let metrics = String::from_utf8(metrics)?;
                write!(file, "{}", metrics)?;
                file.persist(&path)?;
            },
        }

        Ok(())
    }

    pub fn export(self) -> Result<(), ExporterError> {
        debug!("Exporting metrics to file");

        // Get an exporter and export the metrics.
        let exporter = Exporter::new();

        // TODO: Fix this unwrap
        let metrics = exporter.export().unwrap();

        // Write metrics
        self.write(metrics)?;

        Ok(())
    }
}
