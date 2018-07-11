//
// jail_exporter
//
// An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//

extern crate env_logger;
extern crate jail;
extern crate rctl;

#[macro_use]
extern crate log;
#[macro_use]
extern crate prometheus;

use jail::RunningJail;
use prometheus::{
    Encoder,
    IntCounterVec,
    IntGauge,
    IntGaugeVec,
    TextEncoder,
};
use std::collections::HashMap;
use std::sync::Mutex;

// Book keeping for the jail counters.
type CounterBookKeeper = HashMap<String, i64>;
type Rusage = HashMap<rctl::Resource, usize>;
type DeadJails = Vec<String>;
type SeenJails = Vec<String>;

pub struct Metrics {
    // Prometheus time series
    build_info: IntGaugeVec,
    coredumpsize_bytes: IntGaugeVec,
    datasize_bytes: IntGaugeVec,
    memorylocked_bytes: IntGaugeVec,
    memoryuse_bytes: IntGaugeVec,
    msgqsize_bytes: IntGaugeVec,
    shmsize_bytes: IntGaugeVec,
    stacksize_bytes: IntGaugeVec,
    swapuse_bytes: IntGaugeVec,
    vmemoryuse_bytes: IntGaugeVec,
    pcpu_used: IntGaugeVec,
    maxproc: IntGaugeVec,
    msgqqueued: IntGaugeVec,
    nmsgq: IntGaugeVec,
    nsem: IntGaugeVec,
    nsemop: IntGaugeVec,
    nshm: IntGaugeVec,
    nthr: IntGaugeVec,
    openfiles: IntGaugeVec,
    pseudoterminals: IntGaugeVec,
    cputime_seconds_total: IntCounterVec,
    wallclock_seconds_total: IntCounterVec,
    jail_id: IntGaugeVec,
    jail_total: IntGauge,

    // Counter bookkeeping
    cputime_seconds_total_old: Mutex<CounterBookKeeper>,
    wallclock_seconds_total_old: Mutex<CounterBookKeeper>,
}

impl Default for Metrics {
    // Descriptions of these metrics are taken from rctl(8) where possible.
    fn default() -> Self {
        let metrics = Metrics{
            // build info metric
            build_info: register_int_gauge_vec!(
                "jail_exporter_build_info",
                "A metric with a constant '1' value labelled by version \
                from which jail_exporter was built",
                &["version"]
            ).unwrap(),

            // Bytes metrics
            coredumpsize_bytes: register_int_gauge_vec!(
                "jail_coredumpsize_bytes",
                "core dump size, in bytes",
                &["name"]
            ).unwrap(),

            datasize_bytes: register_int_gauge_vec!(
                "jail_datasize_bytes",
                "data size, in bytes",
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

            msgqsize_bytes: register_int_gauge_vec!(
                "jail_msgqsize_bytes",
                "SysV message queue size, in bytes",
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

            // Percent metrics
            pcpu_used: register_int_gauge_vec!(
                "jail_pcpu_used",
                "%CPU, in percents of a single CPU core",
                &["name"]
            ).unwrap(),

            // Random numberical values without a specific unit.
            maxproc: register_int_gauge_vec!(
                "jail_maxproc",
                "number of processes",
                &["name"]
            ).unwrap(),

            msgqqueued: register_int_gauge_vec!(
                "jail_msgqqueued",
                "number of queued SysV messages",
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

            pseudoterminals: register_int_gauge_vec!(
                "jail_pseudoterminals",
                "number of PTYs",
                &["name"]
            ).unwrap(),

            // Seconds metrics
            cputime_seconds_total_old: Mutex::new(
                CounterBookKeeper::new()
            ),
            cputime_seconds_total: register_int_counter_vec!(
                "jail_cputime_seconds_total",
                "CPU time, in seconds",
                &["name"]
            ).unwrap(),

            wallclock_seconds_total_old: Mutex::new(
                CounterBookKeeper::new()
            ),

            wallclock_seconds_total: register_int_counter_vec!(
                "jail_wallclock_seconds_total",
                "wallclock time, in seconds",
                &["name"]
            ).unwrap(),

            // Metrics created by the exporter
            jail_id: register_int_gauge_vec!(
                "jail_id",
                "ID of the named jail.",
                &["name"]
            ).unwrap(),

            jail_total: register_int_gauge!(
                "jail_num",
                "Current number of running jails."
            ).unwrap(),
        };

        let build_info_labels = [env!("CARGO_PKG_VERSION")];
        metrics.build_info.with_label_values(&build_info_labels).set(1);
        metrics
    }
}

impl Metrics {
    pub fn new() -> Self {
        Default::default()
    }

    // Processes the Rusage setting the appripriate time series.
    fn process_rusage(&self, name: &str, metrics: &Rusage) {
        debug!("process_metrics_hash");

        // Convenience variable
        let labels: &[&str] = &[&name];

        for (key, value) in metrics {
            let value = *value as i64;
            match key {
                rctl::Resource::CoreDumpSize => {
                    self.coredumpsize_bytes
                        .with_label_values(labels)
                        .set(value);
                },
                rctl::Resource::CpuTime => {
                    // Get the Book of Old Values
                    let mut book = self.cputime_seconds_total_old
                        .lock()
                        .unwrap();

                    // Get the old value for this jail, if there isn't one,
                    // use 0.
                    let old_value = match book.get(name).cloned() {
                        Some(v) => v,
                        None => 0,
                    };

                    // Work out what our increase should be.
                    // If old_value < value, OS counter has continued to
                    // increment, otherwise it has reset.
                    let inc = if old_value <= value {
                        value - old_value
                    }
                    else {
                        value
                    };

                    // Update book keeping.
                    book.insert(name.to_string(), value);

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
                    // Get the Book of Old Values
                    let mut book = self.wallclock_seconds_total_old
                        .lock()
                        .unwrap();

                    // Get the old value for this jail, if there isn't one,
                    // use 0.
                    let old_value = match book.get(name).cloned() {
                        Some(v) => v,
                        None => 0,
                    };

                    // Work out what our increase should be.
                    // If old_value < value, OS counter has continued to
                    // increment, otherwise it has reset.
                    let inc = if old_value <= value {
                        value - old_value
                    }
                    else {
                        value
                    };

                    // Update book keeping.
                    book.insert(name.to_string(), value);

                    self.wallclock_seconds_total
                        .with_label_values(labels)
                        .inc_by(inc);
                },
                // Intentionally unhandled metrics.
                // These are documented being difficult to observe via rctl(8).
                rctl::Resource::ReadBps
                    | rctl::Resource::WriteBps
                    | rctl::Resource::ReadIops
                    | rctl::Resource::WriteIops => {
                        debug!("Intentionally unhandled metric: {}", key)
                    },
            }
        }
    }

    fn get_jail_metrics(&self) {
        debug!("get_jail_metrics");

        // Set jail_total to zero before gathering.
        self.jail_total.set(0);

        // Get a new vec of seen jails.
        let mut seen = SeenJails::new();

        // Loop over jails.
        for jail in RunningJail::all() {
            let name = jail.name().expect("Could not get jail name");
            let rusage = match jail.racct_statistics() {
                Ok(stats) => stats,
                Err(err) => {
                    err.to_string();
                    break;
                },
            };

            debug!("JID: {}, Name: {:?}", jail.jid, name);

            // Add to our vec of seen jails.
            seen.push(name.to_string());

            // Process rusage for the named jail, setting time series.
            self.process_rusage(&name, &rusage);

            self.jail_id.with_label_values(&[&name]).set(i64::from(jail.jid));
            self.jail_total.set(self.jail_total.get() + 1);
        }

        // Get a list of dead jails based on what we've seen, and reap them.
        // Performed in two steps due to Mutex locking issues.
        let dead = self.dead_jails(&seen);
        self.reap(&dead);
    }

    // Loop over jail names from the previous run, as determined by book
    // keeping, and create a vector of jail names that no longer exist.
    fn dead_jails(&self, seen: &SeenJails) -> DeadJails {
        let mut dead = DeadJails::new();
        let book = self.cputime_seconds_total_old.lock().unwrap();

        for name in book.keys() {
            if !seen.contains(&name) {
                dead.push(name.to_string());
            }
        }

        dead
    }

    // Loop over DeadJails removing old labels and killing old book keeping.
    fn reap(&self, dead: &DeadJails) {
        let mut book = self.cputime_seconds_total_old.lock().unwrap();

        for name in dead {
            self.remove_jail_metrics(&name);
            book.remove(name);
        }
    }

    fn remove_jail_metrics(&self, name: &str) {
        // Convenience variable
        let labels: &[&str] = &[&name];

        // Remove the jail metrics
        self.coredumpsize_bytes.remove_label_values(labels).ok();
        self.datasize_bytes.remove_label_values(labels).ok();
        self.memorylocked_bytes.remove_label_values(labels).ok();
        self.memoryuse_bytes.remove_label_values(labels).ok();
        self.msgqsize_bytes.remove_label_values(labels).ok();
        self.shmsize_bytes.remove_label_values(labels).ok();
        self.stacksize_bytes.remove_label_values(labels).ok();
        self.swapuse_bytes.remove_label_values(labels).ok();
        self.vmemoryuse_bytes.remove_label_values(labels).ok();
        self.pcpu_used.remove_label_values(labels).ok();
        self.maxproc.remove_label_values(labels).ok();
        self.msgqqueued.remove_label_values(labels).ok();
        self.nmsgq.remove_label_values(labels).ok();
        self.nsem.remove_label_values(labels).ok();
        self.nsemop.remove_label_values(labels).ok();
        self.nshm.remove_label_values(labels).ok();
        self.nthr.remove_label_values(labels).ok();
        self.openfiles.remove_label_values(labels).ok();
        self.pseudoterminals.remove_label_values(labels).ok();
        self.cputime_seconds_total.remove_label_values(labels).ok();
        self.wallclock_seconds_total.remove_label_values(labels).ok();
        self.jail_id.remove_label_values(labels).ok();
    }

    pub fn export(&self) -> Vec<u8> {
        // Collect metrics
        self.get_jail_metrics();

        // Gather them
        let metric_families = prometheus::gather();

        // Collect them in a buffer
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        // Return the exported metrics
        buffer
    }
}

// Tests
#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod tests {
    // We need some of the main functions.
    use super::*;

    // We have to register this here as the Prometheus library maintains a
    // global registry. Trying to Metrics::new() in each test will result
    // in errors as duplicate time series will be created.
    lazy_static!{
        static ref TEST_METRICS: Metrics = Metrics::new();
    }

    #[test]
    fn cputime_counter_increase() {
        let names = ["test", "test2"];

        let mut hash = Rusage::new();

        for name in names.iter() {
            let series = TEST_METRICS
                .cputime_seconds_total
                .with_label_values(&[&name]);

            // Initial check, should be zero. We didn't set anything yet.
            assert_eq!(series.get(), 0);

            // First run, adds 1000, total 1000.
            hash.insert(rctl::Resource::CpuTime, 1000);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1000);

            // Second, adds 20, total 1020
            hash.insert(rctl::Resource::CpuTime, 1020);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1020);

            // Third, counter was reset. Adds 10, total 1030.
            hash.insert(rctl::Resource::CpuTime, 10);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1030);

            // Fourth, adds 40, total 1070.
            hash.insert(rctl::Resource::CpuTime, 50);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1070);

            // Fifth, add 0, total 1070
            hash.insert(rctl::Resource::CpuTime, 50);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1070);
        }
    }

    #[test]
    fn wallclock_counter_increase() {
        let names = ["test", "test2"];

        let mut hash = Rusage::new();

        for name in names.iter() {
            let series = TEST_METRICS
                .wallclock_seconds_total
                .with_label_values(&[&name]);

            // Initial check, should be zero. We didn't set anything yet.
            assert_eq!(series.get(), 0);

            // First run, adds 1000, total 1000.
            hash.insert(rctl::Resource::Wallclock, 1000);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1000);

            // Second, adds 20, total 1020
            hash.insert(rctl::Resource::Wallclock, 1020);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1020);

            // Third, counter was reset. Adds 10, total 1030.
            hash.insert(rctl::Resource::Wallclock, 10);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1030);

            // Fourth, adds 40, total 1070.
            hash.insert(rctl::Resource::Wallclock, 50);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1070);

            // Fifth, add 0, total 1070
            hash.insert(rctl::Resource::Wallclock, 50);
            TEST_METRICS.process_metrics_hash(&name, &hash);
            assert_eq!(series.get(), 1070);
        }
    }
}
