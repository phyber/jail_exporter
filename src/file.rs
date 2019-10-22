// File exporter

use crate::errors::Error;
use jail_exporter::Exporter;
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
            Output::Stdout
        }
        else {
            let path = Path::new(&path);
            Output::File(path.into())
        };

        Self {
            dest: output,
        }
    }

    // Handles choosing the correct output type based on path
    fn write(&self, metrics: Vec<u8>) -> Result<(), Error> {
        match &self.dest {
            Output::Stdout => {
                io::stdout().write_all(&metrics)?;
            },
            Output::File(path) => {
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

    pub fn export(self) -> Result<(), Error> {
        // Get an exporter and export the metrics.
        let exporter = Exporter::new();

        // TODO: Fix this unwrap
        let metrics = exporter.export().unwrap();

        // Write metrics
        self.write(metrics)?;

        Ok(())
    }
}
