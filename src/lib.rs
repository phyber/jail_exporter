//! jail_exporter library
//!
//! This lib handles the gathering and exporting of jail metrics.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use jail::RunningJail;
use log::debug;
use prometheus::{
    __register_counter_vec,
    __register_gauge,
    __register_gauge_vec,
    opts,
    register_int_counter_vec,
    register_int_gauge,
    register_int_gauge_vec,
    Encoder,
    IntCounterVec,
    IntGauge,
    IntGaugeVec,
    TextEncoder,
};
use std::collections::HashMap;
use std::sync::{
    Arc,
    Mutex,
};

mod errors;
use errors::Error;

/// Metrics that use bookkeeping
enum BookKept {
    CpuTime(i64),
    Wallclock(i64),
}

/// Book keeping for the jail counters.
type CounterBookKeeper = HashMap<String, i64>;
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
#[derive(Clone)]
pub struct Exporter {
    // Prometheus time series
    // These come from rctl
    coredumpsize_bytes: IntGaugeVec,
    cputime_seconds_total: IntCounterVec,
    datasize_bytes: IntGaugeVec,
    memorylocked_bytes: IntGaugeVec,
    memoryuse_bytes: IntGaugeVec,
    msgqsize_bytes: IntGaugeVec,
    maxproc: IntGaugeVec,
    msgqqueued: IntGaugeVec,
    nmsgq: IntGaugeVec,
    nsem: IntGaugeVec,
    nsemop: IntGaugeVec,
    nshm: IntGaugeVec,
    nthr: IntGaugeVec,
    openfiles: IntGaugeVec,
    pcpu_used: IntGaugeVec,
    pseudoterminals: IntGaugeVec,
    readbps: IntGaugeVec,
    readiops: IntGaugeVec,
    shmsize_bytes: IntGaugeVec,
    stacksize_bytes: IntGaugeVec,
    swapuse_bytes: IntGaugeVec,
    vmemoryuse_bytes: IntGaugeVec,
    wallclock_seconds_total: IntCounterVec,
    writebps: IntGaugeVec,
    writeiops: IntGaugeVec,

    // Metrics this library generates
    build_info: IntGaugeVec,
    jail_id: IntGaugeVec,
    jail_total: IntGauge,

    // Counter bookkeeping
    cputime_seconds_total_old: Arc<Mutex<CounterBookKeeper>>,
    wallclock_seconds_total_old: Arc<Mutex<CounterBookKeeper>>,
}

impl Default for Exporter {
    // Descriptions of these metrics are taken from rctl(8) where possible.
    fn default() -> Self {
        let metrics = Self {
            coredumpsize_bytes: register_int_gauge_vec!(
                "jail_coredumpsize_bytes",
                "core dump size, in bytes",
                &["name"]
            ).unwrap(),

            cputime_seconds_total: register_int_counter_vec!(
                "jail_cputime_seconds_total",
                "CPU time, in seconds",
                &["name"]
            ).unwrap(),

            datasize_bytes: register_int_gauge_vec!(
                "jail_datasize_bytes",
                "data size, in bytes",
                &["name"]
            ).unwrap(),

            maxproc: register_int_gauge_vec!(
                "jail_maxproc",
                "number of processes",
                &["name"]
            ).unwrap(),

            memorylocked_bytes: register_int_gauge_vec!(
                "jail_memorylocked_bytes",
                "locked memory, in bytes",
                &["name"]
            ).unwrap(),

            memoryuse_bytes: register_int_gauge_vec!(
                "jail_memoryuse_bytes",
                "resident set size, in bytes",
                &["name"]
            ).unwrap(),

            msgqqueued: register_int_gauge_vec!(
                "jail_msgqqueued",
                "number of queued SysV messages",
                &["name"]
            ).unwrap(),

            msgqsize_bytes: register_int_gauge_vec!(
                "jail_msgqsize_bytes",
                "SysV message queue size, in bytes",
                &["name"]
            ).unwrap(),

            nmsgq: register_int_gauge_vec!(
                "jail_nmsgq",
                "number of SysV message queues",
                &["name"]
            ).unwrap(),

            nsem: register_int_gauge_vec!(
                "jail_nsem",
                "number of SysV semaphores",
                &["name"]
            ).unwrap(),

            nsemop: register_int_gauge_vec!(
                "jail_nsemop",
                "number of SysV semaphores modified in a single semop(2) call",
                &["name"]
            ).unwrap(),

            nshm: register_int_gauge_vec!(
                "jail_nshm",
                "number of SysV shared memory segments",
                &["name"]
            ).unwrap(),

            nthr: register_int_gauge_vec!(
                "jail_nthr",
                "number of threads",
                &["name"]
            ).unwrap(),

            openfiles: register_int_gauge_vec!(
                "jail_openfiles",
                "file descriptor table size",
                &["name"]
            ).unwrap(),

            pcpu_used: register_int_gauge_vec!(
                "jail_pcpu_used",
                "%CPU, in percents of a single CPU core",
                &["name"]
            ).unwrap(),

            pseudoterminals: register_int_gauge_vec!(
                "jail_pseudoterminals",
                "number of PTYs",
                &["name"]
            ).unwrap(),

            readbps: register_int_gauge_vec!(
                "jail_readbps",
                "filesystem reads, in bytes per second",
                &["name"]
            ).unwrap(),

            readiops: register_int_gauge_vec!(
                "jail_readiops",
                "filesystem reads, in operations per second",
                &["name"]
            ).unwrap(),

            shmsize_bytes: register_int_gauge_vec!(
                "jail_shmsize_bytes",
                "SysV shared memory size, in bytes",
                &["name"]
            ).unwrap(),

            stacksize_bytes: register_int_gauge_vec!(
                "jail_stacksize_bytes",
                "stack size, in bytes",
                &["name"]
            ).unwrap(),

            swapuse_bytes: register_int_gauge_vec!(
                "jail_swapuse_bytes",
                "swap space that may be reserved or used, in bytes",
                &["name"]
            ).unwrap(),

            vmemoryuse_bytes: register_int_gauge_vec!(
                "jail_vmemoryuse_bytes",
                "address space limit, in bytes",
                &["name"]
            ).unwrap(),

            wallclock_seconds_total: register_int_counter_vec!(
                "jail_wallclock_seconds_total",
                "wallclock time, in seconds",
                &["name"]
            ).unwrap(),

            writebps: register_int_gauge_vec!(
                "jail_writebps",
                "filesystem writes, in bytes per second",
                &["name"]
            ).unwrap(),

            writeiops: register_int_gauge_vec!(
                "jail_writeiops",
                "filesystem writes, in operations per second",
                &["name"]
            ).unwrap(),

            // Metrics created by the exporter
            build_info: register_int_gauge_vec!(
                "jail_exporter_build_info",
                "A metric with a constant '1' value labelled by version \
                 from which jail_exporter was built",
                &["version"]
            ).unwrap(),

            jail_id: register_int_gauge_vec!(
                "jail_id",
                "ID of the named jail.",
                &["name"]
            ).unwrap(),

            jail_total: register_int_gauge!(
                "jail_num",
                "Current number of running jails."
            ).unwrap(),

            // Book keeping
            cputime_seconds_total_old: Arc::new(Mutex::new(
                    CounterBookKeeper::new()
                    )),
            wallclock_seconds_total_old: Arc::new(Mutex::new(
                    CounterBookKeeper::new()
                    )),
        };

        let build_info_labels = [env!("CARGO_PKG_VERSION")];
        metrics.build_info.with_label_values(&build_info_labels).set(1);

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
        Default::default()
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
    pub fn export(&self) -> Result<ExportedMetrics, Error> {
        // Collect metrics
        self.get_jail_metrics()?;

        // Gather them
        let metric_families = prometheus::gather();

        // Collect them in a buffer
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer)?;

        // Return the exported metrics
        Ok(buffer)
    }

    /// Updates the book for the given metric and returns the amount the value
    /// has increased by.
    fn update_metric_book(&self, name: &str, resource: &BookKept) -> i64 {
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
        let old_value = match book.get(name).cloned() {
            None    => 0,
            Some(v) => v,
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
        let labels: &[&str] = &[&name];

        for (key, value) in metrics {
            // Convert the usize to an i64.
            let value = *value as i64;

            match key {
                rctl::Resource::CoreDumpSize => {
                    self.coredumpsize_bytes
                        .with_label_values(labels)
                        .set(value);
                },
                rctl::Resource::CpuTime => {
                    let inc = self.update_metric_book(
                        &name,
                        &BookKept::CpuTime(value)
                    );

                    self.cputime_seconds_total
                        .with_label_values(labels)
                        .inc_by(inc);
                },
                rctl::Resource::DataSize => {
                    self.datasize_bytes.with_label_values(labels).set(value);
                },
                rctl::Resource::MaxProcesses => {
                    self.maxproc.with_label_values(labels).set(value);
                },
                rctl::Resource::MemoryLocked => {
                    self.memorylocked_bytes
                        .with_label_values(labels)
                        .set(value);
                },
                rctl::Resource::MemoryUse => {
                    self.memoryuse_bytes.with_label_values(labels).set(value);
                },
                rctl::Resource::MsgqQueued => {
                    self.msgqqueued.with_label_values(labels).set(value);
                },
                rctl::Resource::MsgqSize => {
                    self.msgqsize_bytes.with_label_values(labels).set(value);
                },
                rctl::Resource::NMsgq => {
                    self.nmsgq.with_label_values(labels).set(value);
                },
                rctl::Resource::Nsem => {
                    self.nsem.with_label_values(labels).set(value);
                },
                rctl::Resource::NSemop => {
                    self.nsemop.with_label_values(labels).set(value);
                },
                rctl::Resource::NShm => {
                    self.nshm.with_label_values(labels).set(value);
                },
                rctl::Resource::NThreads => {
                    self.nthr.with_label_values(labels).set(value);
                },
                rctl::Resource::OpenFiles => {
                    self.openfiles.with_label_values(labels).set(value);
                },
                rctl::Resource::PercentCpu => {
                    self.pcpu_used.with_label_values(labels).set(value);
                },
                rctl::Resource::PseudoTerminals => {
                    self.pseudoterminals.with_label_values(labels).set(value);
                },
                rctl::Resource::ReadBps => {
                    self.readbps.with_label_values(labels).set(value);
                },
                rctl::Resource::ReadIops => {
                    self.readiops.with_label_values(labels).set(value);
                },
                rctl::Resource::ShmSize => {
                    self.shmsize_bytes.with_label_values(labels).set(value);
                },
                rctl::Resource::StackSize => {
                    self.stacksize_bytes.with_label_values(labels).set(value);
                },
                rctl::Resource::SwapUse => {
                    self.swapuse_bytes.with_label_values(labels).set(value);
                },
                rctl::Resource::VMemoryUse => {
                    self.vmemoryuse_bytes.with_label_values(labels).set(value);
                },
                rctl::Resource::Wallclock => {
                    let inc = self.update_metric_book(
                        &name,
                        &BookKept::Wallclock(value)
                    );

                    self.wallclock_seconds_total
                        .with_label_values(labels)
                        .inc_by(inc);
                },
                rctl::Resource::WriteBps => {
                    self.writebps.with_label_values(labels).set(value)
                },
                rctl::Resource::WriteIops => {
                    self.writeiops.with_label_values(labels).set(value)
                },
            }
        }
    }

    fn get_jail_metrics(&self) -> Result<(), Error> {
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
            seen.push(name.to_owned());

            // Process rusage for the named jail, setting time series.
            self.process_rusage(&name, &rusage);

            self.jail_id.with_label_values(&[&name]).set(i64::from(jail.jid));
            self.jail_total.set(self.jail_total.get() + 1);
        }

        // Get a list of dead jails based on what we've seen, and reap them.
        // Performed in two steps due to Mutex locking issues.
        let dead = self.dead_jails(seen);
        self.reap(dead);

        Ok(())
    }

    // Loop over jail names from the previous run, as determined by book
    // keeping, and create a vector of jail names that no longer exist.
    fn dead_jails(&self, seen: SeenJails) -> DeadJails {
        let book = self.cputime_seconds_total_old.lock().unwrap();

        book
            .keys()
            .filter(|n| !seen.contains(&n))
            .map(|n| n.to_owned())
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
        let labels: &[&str] = &[&name];

        // Remove the jail metrics
        self.coredumpsize_bytes.remove_label_values(labels).ok();
        self.cputime_seconds_total.remove_label_values(labels).ok();
        self.datasize_bytes.remove_label_values(labels).ok();
        self.maxproc.remove_label_values(labels).ok();
        self.memorylocked_bytes.remove_label_values(labels).ok();
        self.memoryuse_bytes.remove_label_values(labels).ok();
        self.msgqqueued.remove_label_values(labels).ok();
        self.msgqsize_bytes.remove_label_values(labels).ok();
        self.nmsgq.remove_label_values(labels).ok();
        self.nsem.remove_label_values(labels).ok();
        self.nsemop.remove_label_values(labels).ok();
        self.nshm.remove_label_values(labels).ok();
        self.nthr.remove_label_values(labels).ok();
        self.openfiles.remove_label_values(labels).ok();
        self.pcpu_used.remove_label_values(labels).ok();
        self.pseudoterminals.remove_label_values(labels).ok();
        self.readbps.remove_label_values(labels).ok();
        self.readiops.remove_label_values(labels).ok();
        self.shmsize_bytes.remove_label_values(labels).ok();
        self.stacksize_bytes.remove_label_values(labels).ok();
        self.swapuse_bytes.remove_label_values(labels).ok();
        self.vmemoryuse_bytes.remove_label_values(labels).ok();
        self.wallclock_seconds_total.remove_label_values(labels).ok();
        self.writebps.remove_label_values(labels).ok();
        self.writeiops.remove_label_values(labels).ok();

        // Reset metrics we generated.
        self.jail_id.remove_label_values(labels).ok();

        // Kill the books for dead jails.
        let books = [
            &self.cputime_seconds_total_old,
            &self.wallclock_seconds_total_old,
        ];

        for book in books.iter() {
            let mut book = book.lock().unwrap();
            book.remove(name);
        }
    }
}

// Tests
#[cfg(test)]
mod tests {
    // We need some of the main functions.
    use super::*;
    use lazy_static::lazy_static;
    use pretty_assertions::assert_eq;

    // We have to register this here as the Prometheus library maintains a
    // global registry. Trying to Metrics::new() in each test will result
    // in errors as duplicate time series will be created.
    lazy_static! {
        static ref TEST_EXPORTER: Exporter = Exporter::new();
    }

    #[test]
    fn cputime_counter_increase() {
        let names = ["test", "test2"];

        let mut hash = Rusage::new();

        for name in names.iter() {
            let series = TEST_EXPORTER
                .cputime_seconds_total
                .with_label_values(&[&name]);

            // Initial check, should be zero. We didn't set anything yet.
            assert_eq!(series.get(), 0);

            // First run, adds 1000, total 1000.
            hash.insert(rctl::Resource::CpuTime, 1000);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1000);

            // Second, adds 20, total 1020
            hash.insert(rctl::Resource::CpuTime, 1020);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1020);

            // Third, counter was reset. Adds 10, total 1030.
            hash.insert(rctl::Resource::CpuTime, 10);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1030);

            // Fourth, adds 40, total 1070.
            hash.insert(rctl::Resource::CpuTime, 50);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1070);

            // Fifth, add 0, total 1070
            hash.insert(rctl::Resource::CpuTime, 50);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1070);
        }
    }

    #[test]
    fn wallclock_counter_increase() {
        let names = ["test", "test2"];

        let mut hash = Rusage::new();

        for name in names.iter() {
            let series = TEST_EXPORTER
                .wallclock_seconds_total
                .with_label_values(&[&name]);

            // Initial check, should be zero. We didn't set anything yet.
            assert_eq!(series.get(), 0);

            // First run, adds 1000, total 1000.
            hash.insert(rctl::Resource::Wallclock, 1000);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1000);

            // Second, adds 20, total 1020
            hash.insert(rctl::Resource::Wallclock, 1020);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1020);

            // Third, counter was reset. Adds 10, total 1030.
            hash.insert(rctl::Resource::Wallclock, 10);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1030);

            // Fourth, adds 40, total 1070.
            hash.insert(rctl::Resource::Wallclock, 50);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1070);

            // Fifth, add 0, total 1070
            hash.insert(rctl::Resource::Wallclock, 50);
            TEST_EXPORTER.process_rusage(&name, &hash);
            assert_eq!(series.get(), 1070);
        }
    }
}
