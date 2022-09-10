//! `jail_exporter` library
//!
//! This lib handles the gathering and exporting of jail metrics.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use crate::errors::ExporterError;
use crate::httpd::{
    Collector,
    HttpdError,
};
use jail::RunningJail;
use log::debug;
use prometheus_client::encoding::text::{
    Encode,
    encode,
};
use prometheus_client::metrics::{
    counter::Counter,
    family::Family,
    gauge::Gauge,
    info::Info,
};
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::sync::{
    Arc,
    Mutex,
};

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
struct NameLabel {
    // Jail name.
    name: String,
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
struct VersionLabels {
    rustversion: String,
    version: String,
}

/// Metrics that use bookkeeping
enum BookKept {
    CpuTime(u64),
    Wallclock(u64),
}

/// Book keeping for the jail counters.
type CounterBookKeeper = HashMap<String, u64>;
type Rusage = HashMap<rctl::Resource, usize>;

/// Vector of String representing jails that have disappeared since the last
/// scrape.
type DeadJails = Vec<String>;

/// Vector of String representing jails that we have seen during the current
/// scrape.
type SeenJails = Vec<String>;

/// Vector of u8 representing gathered metrics.
type ExportedMetrics = Vec<u8>;

/// Exporter structure containing the time series that are being tracked.
pub struct Exporter {
    // Exporter Registry
    registry: Registry,

    // Prometheus time series
    // These come from rctl
    coredumpsize_bytes:      Family<NameLabel, Gauge>,
    cputime_seconds_total:   Family<NameLabel, Counter>,
    datasize_bytes:          Family<NameLabel, Gauge>,
    memorylocked_bytes:      Family<NameLabel, Gauge>,
    memoryuse_bytes:         Family<NameLabel, Gauge>,
    msgqsize_bytes:          Family<NameLabel, Gauge>,
    maxproc:                 Family<NameLabel, Gauge>,
    msgqqueued:              Family<NameLabel, Gauge>,
    nmsgq:                   Family<NameLabel, Gauge>,
    nsem:                    Family<NameLabel, Gauge>,
    nsemop:                  Family<NameLabel, Gauge>,
    nshm:                    Family<NameLabel, Gauge>,
    nthr:                    Family<NameLabel, Gauge>,
    openfiles:               Family<NameLabel, Gauge>,
    pcpu_used:               Family<NameLabel, Gauge>,
    pseudoterminals:         Family<NameLabel, Gauge>,
    readbps:                 Family<NameLabel, Gauge>,
    readiops:                Family<NameLabel, Gauge>,
    shmsize_bytes:           Family<NameLabel, Gauge>,
    stacksize_bytes:         Family<NameLabel, Gauge>,
    swapuse_bytes:           Family<NameLabel, Gauge>,
    vmemoryuse_bytes:        Family<NameLabel, Gauge>,
    wallclock_seconds_total: Family<NameLabel, Counter>,
    writebps:                Family<NameLabel, Gauge>,
    writeiops:               Family<NameLabel, Gauge>,

    // Metrics this library generates
    jail_id:    Family<NameLabel, Gauge>,
    jail_total: Gauge,

    // Counter bookkeeping
    cputime_seconds_total_old:   Arc<Mutex<CounterBookKeeper>>,
    wallclock_seconds_total_old: Arc<Mutex<CounterBookKeeper>>,
}

/// Register a Counter Family with the Registry
#[macro_export]
macro_rules! register_int_counter_vec_with_registry {
    ($NAME:expr, $HELP:expr, $LABELS:ty, $REGISTRY:ident $(,)?) => {{
        let family = Family::<$LABELS, Counter>::default();

        $REGISTRY.register($NAME, $HELP, Box::new(family.clone()));

        family
    }};
}

/// Register a Gauge with the Registry
#[macro_export]
macro_rules! register_int_gauge_with_registry {
    ($NAME:expr, $HELP:expr, $REGISTRY:ident $(,)?) => {{
        let gauge = Gauge::default();

        $REGISTRY.register($NAME, $HELP, Box::new(gauge.clone()));

        gauge
    }};
}

/// Register a Gauge Family with the Registry
#[macro_export]
macro_rules! register_int_gauge_vec_with_registry {
    ($NAME:expr, $HELP:expr, $LABELS:ty, $REGISTRY:ident $(,)?) => {{
        let family = Family::<$LABELS, Gauge>::default();

        $REGISTRY.register($NAME, $HELP, Box::new(family.clone()));

        family
    }};
}

/// Register an Info metric with the Registry
#[macro_export]
macro_rules! register_info_with_registry {
    ($NAME:expr, $HELP:expr, $LABELS:expr, $REGISTRY:ident $(,)?) => {{
        let info = Info::new($LABELS);

        $REGISTRY.register($NAME, $HELP, Box::new(info));
    }};
}

impl Default for Exporter {
    // Descriptions of these metrics are taken from rctl(8) where possible.
    fn default() -> Self {
        // We want to set this as a field in the returned struct, as well as
        // pass it to the macros.
        let mut registry = <Registry>::with_prefix("jail");

        // Static info metric, doesn't need to be in the struct.
        register_info_with_registry!(
            "exporter_build",
            "A metric with constant '1' value labelled by version \
             from which jail_exporter was built",
             VersionLabels {
                rustversion: env!("RUSTC_VERSION").to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
             },
             registry,
        );

        let metrics = Self {
            coredumpsize_bytes: register_int_gauge_vec_with_registry!(
                "coredumpsize_bytes",
                "core dump size, in bytes",
                NameLabel,
                registry,
            ),

            cputime_seconds_total: register_int_counter_vec_with_registry!(
                "cputime_seconds_total",
                "CPU time, in seconds",
                NameLabel,
                registry,
            ),

            datasize_bytes: register_int_gauge_vec_with_registry!(
                "datasize_bytes",
                "data size, in bytes",
                NameLabel,
                registry,
            ),

            maxproc: register_int_gauge_vec_with_registry!(
                "maxproc",
                "number of processes",
                NameLabel,
                registry,
            ),

            memorylocked_bytes: register_int_gauge_vec_with_registry!(
                "memorylocked_bytes",
                "locked memory, in bytes",
                NameLabel,
                registry,
            ),

            memoryuse_bytes: register_int_gauge_vec_with_registry!(
                "memoryuse_bytes",
                "resident set size, in bytes",
                NameLabel,
                registry,
            ),

            msgqqueued: register_int_gauge_vec_with_registry!(
                "msgqqueued",
                "number of queued SysV messages",
                NameLabel,
                registry,
            ),

            msgqsize_bytes: register_int_gauge_vec_with_registry!(
                "msgqsize_bytes",
                "SysV message queue size, in bytes",
                NameLabel,
                registry,
            ),

            nmsgq: register_int_gauge_vec_with_registry!(
                "nmsgq",
                "number of SysV message queues",
                NameLabel,
                registry,
            ),

            nsem: register_int_gauge_vec_with_registry!(
                "nsem",
                "number of SysV semaphores",
                NameLabel,
                registry,
            ),

            nsemop: register_int_gauge_vec_with_registry!(
                "nsemop",
                "number of SysV semaphores modified in a single semop(2) call",
                NameLabel,
                registry,
            ),

            nshm: register_int_gauge_vec_with_registry!(
                "nshm",
                "number of SysV shared memory segments",
                NameLabel,
                registry,
            ),

            nthr: register_int_gauge_vec_with_registry!(
                "nthr",
                "number of threads",
                NameLabel,
                registry,
            ),

            openfiles: register_int_gauge_vec_with_registry!(
                "openfiles",
                "file descriptor table size",
                NameLabel,
                registry,
            ),

            pcpu_used: register_int_gauge_vec_with_registry!(
                "pcpu_used",
                "%CPU, in percents of a single CPU core",
                NameLabel,
                registry,
            ),

            pseudoterminals: register_int_gauge_vec_with_registry!(
                "pseudoterminals",
                "number of PTYs",
                NameLabel,
                registry,
            ),

            readbps: register_int_gauge_vec_with_registry!(
                "readbps",
                "filesystem reads, in bytes per second",
                NameLabel,
                registry,
            ),

            readiops: register_int_gauge_vec_with_registry!(
                "readiops",
                "filesystem reads, in operations per second",
                NameLabel,
                registry,
            ),

            shmsize_bytes: register_int_gauge_vec_with_registry!(
                "shmsize_bytes",
                "SysV shared memory size, in bytes",
                NameLabel,
                registry,
            ),

            stacksize_bytes: register_int_gauge_vec_with_registry!(
                "stacksize_bytes",
                "stack size, in bytes",
                NameLabel,
                registry,
            ),

            swapuse_bytes: register_int_gauge_vec_with_registry!(
                "swapuse_bytes",
                "swap space that may be reserved or used, in bytes",
                NameLabel,
                registry,
            ),

            vmemoryuse_bytes: register_int_gauge_vec_with_registry!(
                "vmemoryuse_bytes",
                "address space limit, in bytes",
                NameLabel,
                registry,
            ),

            wallclock_seconds_total: register_int_counter_vec_with_registry!(
                "wallclock_seconds_total",
                "wallclock time, in seconds",
                NameLabel,
                registry,
            ),

            writebps: register_int_gauge_vec_with_registry!(
                "writebps",
                "filesystem writes, in bytes per second",
                NameLabel,
                registry,
            ),

            writeiops: register_int_gauge_vec_with_registry!(
                "writeiops",
                "filesystem writes, in operations per second",
                NameLabel,
                registry,
            ),

            // Metrics created by the exporter
            jail_id: register_int_gauge_vec_with_registry!(
                "id",
                "ID of the named jail.",
                NameLabel,
                registry,
            ),

            jail_total: register_int_gauge_with_registry!(
                "num",
                "Current number of running jails.",
                registry,
            ),

            // Registry must be added after the macros making use of it
            registry: registry,

            // Book keeping
            cputime_seconds_total_old: Arc::new(Mutex::new(
                CounterBookKeeper::new()
            )),
            wallclock_seconds_total_old: Arc::new(Mutex::new(
                CounterBookKeeper::new()
            )),
        };

        metrics
    }
}

/// Exporter implementation
impl Exporter {
    /// Return a new Exporter instance.
    ///
    /// This will create the initial time series and return a metrics struct.
    ///
    /// # Example
    ///
    /// ```
    /// let exporter = jail_exporter::Exporter::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Collect and export the rctl metrics.
    ///
    /// This will return a `Vec<u8>` representing the Prometheus metrics
    /// text format.
    ///
    /// # Example
    ///
    /// ```
    /// # let exporter = jail_exporter::Exporter::new();
    /// let output = exporter.export();
    /// ```
    pub fn export(&self) -> Result<ExportedMetrics, ExporterError> {
        // Collect metrics
        self.get_jail_metrics()?;

        // Collect them in a buffer
        let mut buffer = vec![];
        encode(&mut buffer, &self.registry).expect("encode");

        // Return the exported metrics
        Ok(buffer)
    }

    /// Updates the book for the given metric and returns the amount the value
    /// has increased by.
    fn update_metric_book(&self, name: &str, resource: &BookKept) -> u64 {
        // Get the Book of Old Values and the current value.
        let (mut book, value) = match *resource {
            BookKept::CpuTime(v) => {
                let book = self.cputime_seconds_total_old.lock().unwrap();
                (book, v)
            },
            BookKept::Wallclock(v) => {
                let book = self.wallclock_seconds_total_old.lock().unwrap();
                (book, v)
            },
        };

        // Get the old value for this jail, if there isn't one, use 0.
        let old_value = match book.get(name) {
            None    => 0,
            Some(v) => *v,
        };

        // Work out what our increase should be.
        // If old_value <= value, OS counter has continued to increment,
        // otherwise it has reset.
        let inc = if old_value <= value {
            value - old_value
        }
        else {
            value
        };

        // Update book keeping.
        book.insert(name.to_owned(), value);

        // Return computed increase
        inc
    }

    /// Processes the Rusage setting the appripriate time series.
    fn process_rusage(&self, name: &str, metrics: &Rusage) {
        debug!("process_metrics_hash");

        // Convenience variable
        let labels = &NameLabel {
            name: name.to_string(),
        };

        for (key, value) in metrics {
            // Convert the usize to an i64 as the majority of metrics take
            // this.
            // Counters cast this back to a u64, which should be safe as it
            // was a usize originally.
            let value = *value as u64;

            match key {
                rctl::Resource::CoreDumpSize => {
                    self.coredumpsize_bytes
                        .get_or_create(labels)
                        .set(value);
                },
                rctl::Resource::CpuTime => {
                    let inc = self.update_metric_book(
                        name,
                        &BookKept::CpuTime(value as u64)
                    );

                    self.cputime_seconds_total
                        .get_or_create(labels)
                        .inc_by(inc);
                },
                rctl::Resource::DataSize => {
                    self.datasize_bytes.get_or_create(labels).set(value);
                },
                rctl::Resource::MaxProcesses => {
                    self.maxproc.get_or_create(labels).set(value);
                },
                rctl::Resource::MemoryLocked => {
                    self.memorylocked_bytes
                        .get_or_create(labels)
                        .set(value);
                },
                rctl::Resource::MemoryUse => {
                    self.memoryuse_bytes.get_or_create(labels).set(value);
                },
                rctl::Resource::MsgqQueued => {
                    self.msgqqueued.get_or_create(labels).set(value);
                },
                rctl::Resource::MsgqSize => {
                    self.msgqsize_bytes.get_or_create(labels).set(value);
                },
                rctl::Resource::NMsgq => {
                    self.nmsgq.get_or_create(labels).set(value);
                },
                rctl::Resource::Nsem => {
                    self.nsem.get_or_create(labels).set(value);
                },
                rctl::Resource::NSemop => {
                    self.nsemop.get_or_create(labels).set(value);
                },
                rctl::Resource::NShm => {
                    self.nshm.get_or_create(labels).set(value);
                },
                rctl::Resource::NThreads => {
                    self.nthr.get_or_create(labels).set(value);
                },
                rctl::Resource::OpenFiles => {
                    self.openfiles.get_or_create(labels).set(value);
                },
                rctl::Resource::PercentCpu => {
                    self.pcpu_used.get_or_create(labels).set(value);
                },
                rctl::Resource::PseudoTerminals => {
                    self.pseudoterminals.get_or_create(labels).set(value);
                },
                rctl::Resource::ReadBps => {
                    self.readbps.get_or_create(labels).set(value);
                },
                rctl::Resource::ReadIops => {
                    self.readiops.get_or_create(labels).set(value);
                },
                rctl::Resource::ShmSize => {
                    self.shmsize_bytes.get_or_create(labels).set(value);
                },
                rctl::Resource::StackSize => {
                    self.stacksize_bytes.get_or_create(labels).set(value);
                },
                rctl::Resource::SwapUse => {
                    self.swapuse_bytes.get_or_create(labels).set(value);
                },
                rctl::Resource::VMemoryUse => {
                    self.vmemoryuse_bytes.get_or_create(labels).set(value);
                },
                rctl::Resource::Wallclock => {
                    let inc = self.update_metric_book(
                        name,
                        &BookKept::Wallclock(value as u64)
                    );

                    self.wallclock_seconds_total
                        .get_or_create(labels)
                        .inc_by(inc);
                },
                rctl::Resource::WriteBps => {
                    self.writebps.get_or_create(labels).set(value);
                },
                rctl::Resource::WriteIops => {
                    self.writeiops.get_or_create(labels).set(value);
                },
            }
        }
    }

    fn get_jail_metrics(&self) -> Result<(), ExporterError> {
        debug!("get_jail_metrics");

        // Set jail_total to zero before gathering.
        self.jail_total.set(0);

        // Get a new vec of seen jails.
        let mut seen = SeenJails::new();

        // Loop over jails.
        for jail in RunningJail::all() {
            let name = jail.name()?;
            let rusage = jail.racct_statistics()?;

            debug!("JID: {}, Name: {:?}", jail.jid, name);

            // Add to our vec of seen jails.
            seen.push(name.clone());

            // Process rusage for the named jail, setting time series.
            self.process_rusage(&name, &rusage);

            let labels = &NameLabel {
                name: name,
            };

            self.jail_id.get_or_create(labels).set(jail.jid as u64);
            self.jail_total.set(self.jail_total.get() + 1);
        }

        // Get a list of dead jails based on what we've seen, and reap them.
        // Performed in two steps due to Mutex locking issues.
        let dead = self.dead_jails(&seen);
        self.reap(dead);

        Ok(())
    }

    // Loop over jail names from the previous run, as determined by book
    // keeping, and create a vector of jail names that no longer exist.
    fn dead_jails(&self, seen: &SeenJails) -> DeadJails {
        let book = self.cputime_seconds_total_old.lock().unwrap();

        book
            .keys()
            .filter(|n| !seen.contains(n))
            //.map(|n| n.clone())
            .cloned()
            .collect()
    }

    // Loop over DeadJails removing old labels and killing old book keeping.
    fn reap(&self, dead: DeadJails) {
        for name in dead {
            self.remove_jail_metrics(&name);
        }
    }

    fn remove_jail_metrics(&self, name: &str) {
        // Convenience variable
        let _labels = &NameLabel {
            name: name.to_string(),
        };

        // Remove the jail metrics
        //self.coredumpsize_bytes.remove_label_set(labels).ok();
        //self.cputime_seconds_total.remove_label_set(labels).ok();
        //self.datasize_bytes.remove_label_set(labels).ok();
        //self.maxproc.remove_label_set(labels).ok();
        //self.memorylocked_bytes.remove_label_set(labels).ok();
        //self.memoryuse_bytes.remove_label_set(labels).ok();
        //self.msgqqueued.remove_label_set(labels).ok();
        //self.msgqsize_bytes.remove_label_set(labels).ok();
        //self.nmsgq.remove_label_set(labels).ok();
        //self.nsem.remove_label_set(labels).ok();
        //self.nsemop.remove_label_set(labels).ok();
        //self.nshm.remove_label_set(labels).ok();
        //self.nthr.remove_label_set(labels).ok();
        //self.openfiles.remove_label_set(labels).ok();
        //self.pcpu_used.remove_label_set(labels).ok();
        //self.pseudoterminals.remove_label_set(labels).ok();
        //self.readbps.remove_label_set(labels).ok();
        //self.readiops.remove_label_set(labels).ok();
        //self.shmsize_bytes.remove_label_set(labels).ok();
        //self.stacksize_bytes.remove_label_set(labels).ok();
        //self.swapuse_bytes.remove_label_set(labels).ok();
        //self.vmemoryuse_bytes.remove_label_set(labels).ok();
        //self.wallclock_seconds_total.remove_label_set(labels).ok();
        //self.writebps.remove_label_set(labels).ok();
        //self.writeiops.remove_label_set(labels).ok();

        //// Reset metrics we generated.
        //self.jail_id.remove_label_set(labels).ok();

        // Kill the books for dead jails.
        let books = [
            &self.cputime_seconds_total_old,
            &self.wallclock_seconds_total_old,
        ];

        for book in &books {
            let mut book = book.lock().unwrap();
            book.remove(name);
        }
    }
}

/// Implements the Collector trait used by the Httpd component.
impl Collector for Exporter {
    fn collect(&self) -> Result<Vec<u8>, HttpdError> {
        self.export()
            .map_err(|e| HttpdError::CollectorError(e.to_string()))
    }
}

// Tests
#[cfg(test)]
mod tests {
    // We need some of the main functions.
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn cputime_counter_increase() {
        let names = ["test", "test2"];
        let mut hash = Rusage::new();
        let exporter = Exporter::new();

        for name in names.iter() {
            let series = exporter
                .cputime_seconds_total
                .with_label_values(&[&name]);

            // Initial check, should be zero. We didn't set anything yet.
            assert_eq!(series.get(), 0);

            // First run, adds 1000, total 1000.
            hash.insert(rctl::Resource::CpuTime, 1000);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1000);

            // Second, adds 20, total 1020
            hash.insert(rctl::Resource::CpuTime, 1020);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1020);

            // Third, counter was reset. Adds 10, total 1030.
            hash.insert(rctl::Resource::CpuTime, 10);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1030);

            // Fourth, adds 40, total 1070.
            hash.insert(rctl::Resource::CpuTime, 50);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1070);

            // Fifth, add 0, total 1070
            hash.insert(rctl::Resource::CpuTime, 50);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1070);
        }
    }

    #[test]
    fn dead_jails_ok() {
        let names = ["test_a", "test_b", "test_c"];
        let mut hash = Rusage::new();
        let exporter = Exporter::new();

        // Create some metrics for test_{a,b,c}.
        for name in names.iter() {
            hash.insert(rctl::Resource::CpuTime, 1000);
            exporter.process_rusage(&name, &hash);
        }

        // Now, create a seen array containing only a and c.
        let mut seen = SeenJails::new();
        seen.push("test_a".into());
        seen.push("test_c".into());

        // Workout which jails are dead, it should be b.
        let dead = exporter.dead_jails(&seen);
        let ok: DeadJails = vec![
            "test_b".into(),
        ];

        assert_eq!(ok, dead);
    }

    #[test]
    fn reap_ok() {
        let names = ["test_a", "test_b", "test_c"];
        let mut hash = Rusage::new();
        let exporter = Exporter::new();

        // Create some metrics for test_{a,b,c}.
        for name in names.iter() {
            hash.insert(rctl::Resource::CpuTime, 1000);
            exporter.process_rusage(&name, &hash);
        }

        // Now, create a seen array containing only a and c.
        let mut seen = SeenJails::new();
        seen.push("test_a".into());
        seen.push("test_c".into());

        let dead_jail = "test_b";
        let series = exporter
            .cputime_seconds_total
            .with_label_values(&[dead_jail]);

        assert_eq!(series.get(), 1000);

        // Workout which jails are dead, it should be b.
        let dead = exporter.dead_jails(&seen);
        exporter.reap(dead);

        // We need a new handle on this. Using the old one will present the old
        // value.
        let series = exporter
            .cputime_seconds_total
            .with_label_values(&[dead_jail]);

        assert_eq!(series.get(), 0);
    }

    #[test]
    fn wallclock_counter_increase() {
        let names = ["test", "test2"];
        let mut hash = Rusage::new();
        let exporter = Exporter::new();

        for name in names.iter() {
            let series = exporter
                .wallclock_seconds_total
                .with_label_values(&[&name]);

            // Initial check, should be zero. We didn't set anything yet.
            assert_eq!(series.get(), 0);

            // First run, adds 1000, total 1000.
            hash.insert(rctl::Resource::Wallclock, 1000);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1000);

            // Second, adds 20, total 1020
            hash.insert(rctl::Resource::Wallclock, 1020);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1020);

            // Third, counter was reset. Adds 10, total 1030.
            hash.insert(rctl::Resource::Wallclock, 10);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1030);

            // Fourth, adds 40, total 1070.
            hash.insert(rctl::Resource::Wallclock, 50);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1070);

            // Fifth, add 0, total 1070
            hash.insert(rctl::Resource::Wallclock, 50);
            exporter.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1070);
        }
    }
}
