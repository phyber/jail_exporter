// File exporter

use crate::errors::Error;
use jail_exporter::Exporter;
use std::io::Write;
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
        let parent = path.parent().unwrap();

        Self {
            parent: parent.into(),
            path:   path.into(),
        }
    }

    pub fn export(self) -> Result<(), Error> {
        // Get a temporary file in the parent path of the file we're exporting
        // to.
        // We need to do this since we cannot persist across filesystems.
        let mut file = NamedTempFile::new_in(self.parent)?;

        // Get an exporter and export the metrics.
        let exporter = Exporter::new();

        // TODO: Fix this unwrap
        let metrics = exporter.export().unwrap();

        // Write metrics to the file and persist to the final file path.
        write!(file, "{}", String::from_utf8(metrics)?)?;
        file.persist(self.path)?;

        Ok(())
    }
}
