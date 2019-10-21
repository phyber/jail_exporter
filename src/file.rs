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

pub struct FileExporter {
    parent: PathBuf,
    path: PathBuf,
}

impl FileExporter {
    pub fn new(path: &str) -> Self {
        let path = Path::new(&path);

        // We already vetted the parent in the CLI validator, so unwrap here
        // should be fine.
        // A path of "-" will have a parent of "" for some reason. This works
        // just fine for our purposes.
        let parent = path.parent().unwrap();

        Self {
            parent: parent.into(),
            path:   path.into(),
        }
    }

    // Handles choosing the correct output type based on path
    fn write(&self, metrics: Vec<u8>) -> Result<(), Error> {
        if self.path == Path::new("-") {
            // Output to stdout if requested output path was -
            io::stdout().write_all(&metrics)?;
        }
        else {
            // Otherwise output to the requested file.
            // Get a temporary file in the parent path of the file we're
            // exporting to.
            // We need to do this since we cannot persist across filesystems.
            let mut file = NamedTempFile::new_in(&self.parent)?;

            // Get a string from our utf8
            let metrics = String::from_utf8(metrics)?;

            // Write metrics to the file and persist to the final file path.
            write!(file, "{}", metrics)?;
            file.persist(&self.path)?;
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
