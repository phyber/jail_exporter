/*
 * jail_exporter
 * -------------
 *
 * An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
 *
 */
extern crate hyper;
extern crate libc;
#[macro_use] extern crate clap;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate prometheus;

use hyper::{
    Body,
    Method,
    Request,
    Response,
    Server,
    StatusCode,
};
use hyper::header::CONTENT_TYPE;
use hyper::rt::Future;
use hyper::service::service_fn_ok;
use prometheus::{
    CounterVec,
    Encoder,
    IntCounterVec,
    IntGauge,
    IntGaugeVec,
    TextEncoder,
};
use std::collections::HashMap;
use std::ffi::{
    CStr,
    CString,
};
use std::io::Error;
use std::mem::size_of;
use std::net::SocketAddr;
use std::str::FromStr;

// MetricsHash stores our Key: Value hashmap
type MetricsHash = HashMap<String, i64>;

// Hardcoded for now to the value of security.jail.param.name on FreeBSD 11.1.
const JAIL_NAME_LEN: usize = 256;

// Set to the same value as found in rctl.c in FreeBSD 11.1
const RCTL_DEFAULT_BUFSIZE: usize = 128 * 1024;

// Descriptions of these metrics are taken from rctl(8) where possible.
lazy_static!{
    // Bytes metrics
    static ref JAIL_COREDUMPSIZE_BYTES: IntGaugeVec = register_int_gauge_vec!(
        "jail_coredumpsize_bytes",
        "core dump size, in bytes",
        &["name"]
    ).unwrap();

    static ref JAIL_DATASIZE_BYTES: IntGaugeVec = register_int_gauge_vec!(
        "jail_datasize_bytes",
        "data size, in bytes",
        &["name"]
    ).unwrap();

    static ref JAIL_MEMORYLOCKED_BYTES: IntGaugeVec = register_int_gauge_vec!(
        "jail_memorylocked_bytes",
        "locked memory, in bytes",
        &["name"]
    ).unwrap();

    static ref JAIL_MEMORYUSE_BYTES: IntGaugeVec = register_int_gauge_vec!(
        "jail_memoryuse_bytes",
        "resident set size, in bytes",
        &["name"]
    ).unwrap();

    static ref JAIL_MSGQSIZE_BYTES: IntGaugeVec = register_int_gauge_vec!(
        "jail_msgqsize_bytes",
        "SysV message queue size, in bytes",
        &["name"]
    ).unwrap();

    static ref JAIL_SHMSIZE_BYTES: IntGaugeVec = register_int_gauge_vec!(
        "jail_shmsize_bytes",
        "SysV shared memory size, in bytes",
        &["name"]
    ).unwrap();

    static ref JAIL_STACKSIZE_BYTES: IntGaugeVec = register_int_gauge_vec!(
        "jail_stacksize_bytes",
        "stack size, in bytes",
        &["name"]
    ).unwrap();

    static ref JAIL_SWAPUSE_BYTES: IntGaugeVec = register_int_gauge_vec!(
        "jail_swapuse_bytes",
        "swap space that may be reserved or used, in bytes",
        &["name"]
    ).unwrap();

    static ref JAIL_VMEMORYUSE_BYTES: IntGaugeVec = register_int_gauge_vec!(
        "jail_vmemoryuse_bytes",
        "address space limit, in bytes",
        &["name"]
    ).unwrap();

    // Percent metrics
    static ref JAIL_PCPU_USED: CounterVec = register_counter_vec!(
        "jail_pcpu_used",
        "%CPU, in percents of a single CPU core",
        &["name"]
    ).unwrap();

    // Random numberical values without a specific unit.
    static ref JAIL_MAXPROC: IntGaugeVec = register_int_gauge_vec!(
        "jail_maxproc",
        "number of processes",
        &["name"]
    ).unwrap();

    static ref JAIL_MSGQQUEUED: IntGaugeVec = register_int_gauge_vec!(
        "jail_msgqqueued",
        "number of queued SysV messages",
        &["name"]
    ).unwrap();

    static ref JAIL_NMSGQ: IntGaugeVec = register_int_gauge_vec!(
        "jail_nmsgq",
        "number of SysV message queues",
        &["name"]
    ).unwrap();

    static ref JAIL_NSEM: IntGaugeVec = register_int_gauge_vec!(
        "jail_nsem",
        "number of SysV semaphores",
        &["name"]
    ).unwrap();

    static ref JAIL_NSEMOP: IntGaugeVec = register_int_gauge_vec!(
        "jail_nsemop",
        "number of SysV semaphores modified in a single semop(2) call",
        &["name"]
    ).unwrap();

    static ref JAIL_NSHM: IntGaugeVec = register_int_gauge_vec!(
        "jail_nshm",
        "number of SysV shared memory segments",
        &["name"]
    ).unwrap();

    static ref JAIL_NTHR: IntGaugeVec = register_int_gauge_vec!(
        "jail_nthr",
        "number of threads",
        &["name"]
    ).unwrap();

    static ref JAIL_OPENFILES: IntGaugeVec = register_int_gauge_vec!(
        "jail_openfiles",
        "file descriptor table size",
        &["name"]
    ).unwrap();

    static ref JAIL_PSEUDOTERMINALS: IntGaugeVec = register_int_gauge_vec!(
        "jail_pseudoterminals",
        "number of PTYs",
        &["name"]
    ).unwrap();

    // Seconds metrics
    static ref JAIL_CPUTIME_SECONDS: IntCounterVec = register_int_counter_vec!(
        "jail_cputime_seconds_total",
        "CPU time, in seconds",
        &["name"]
    ).unwrap();

    static ref JAIL_WALLCLOCK_SECONDS: IntCounterVec = register_int_counter_vec!(
        "jail_wallclock_seconds_total",
        "wallclock time, in seconds",
        &["name"]
    ).unwrap();

    // Metrics created by the exporter
    static ref JAIL_ID: IntGaugeVec = register_int_gauge_vec!(
        "jail_id",
        "ID of the named jail.",
        &["name"]
    ).unwrap();

    static ref JAIL_TOTAL: IntGauge = register_int_gauge!(
        "jail_num",
        "Current number of running jails."
    ).unwrap();
}

// Calls libc::jail_get to get jail jid and name.
// Contains unsafe code.
fn jail_get(jid: i32) -> (i32, Option<String>) {
    // Storage for the returned jail name
    let mut value: Vec<u8> = vec![0; JAIL_NAME_LEN];

    // Prepare jail_get parameters.
    let mut iov = vec![
        libc::iovec{
            iov_base: b"lastjid\0" as *const _ as *mut _,
            iov_len:  b"lastjid\0".len(),
        },
        libc::iovec{
            iov_base: &jid as *const _ as *mut _,
            iov_len:  size_of::<i32>(),
        },
        libc::iovec{
            iov_base: b"name\0" as *const _ as *mut _,
            iov_len:  b"name\0".len(),
        },
        libc::iovec{
            iov_base: value.as_mut_ptr() as *mut _,
            iov_len:  JAIL_NAME_LEN,
        },
    ];

    // Execute jail_get with the above parameters
    let jid = unsafe {
        libc::jail_get(
            iov[..].as_mut_ptr() as *mut libc::iovec,
            iov.len() as u32,
            libc::JAIL_DYING,
        )
    };

    // If we found a jail, get its name as a Rust string and return.
    if jid > 0 {
        let name = unsafe {
            CStr::from_ptr(value.as_ptr() as *mut i8)
        }.to_string_lossy().into_owned();

        return (jid, Some(name));
    }

    // We didn't find anything.
    (jid, None)
}

fn rctl_get_jail(jail_name: &str) -> Result<String, Error> {
    extern "C" {
        fn rctl_get_racct(
            inbufp: *const libc::c_char,
            inbuflen: libc::size_t,
            outbufp: *mut libc::c_char,
            outbuflen: libc::size_t,
        ) -> libc::c_int;
    }

    // Create the filter for this specific jail and take the length of the
    // string.
    let mut filter = "jail:".to_string();
    filter.push_str(jail_name);
    let filterlen = filter.len() + 1;

    // C compatible output buffer.
    let outbuflen: usize = RCTL_DEFAULT_BUFSIZE / 4;
    let mut outbuf: Vec<i8> = vec![0; outbuflen];

    // Get the filter as a C string.
    let cfilter = CString::new(filter).unwrap();

    // Unsafe C call to get the jail resource usage.
    let error = unsafe {
        rctl_get_racct(
            cfilter.as_ptr(),
            filterlen,
            outbuf.as_mut_ptr(),
            outbuflen,
        )
    };

    // If everything went well, convert the return C string in the outbuf back
    // into an easily usable Rust string and return.
    if error == 0 {
        let rusage = unsafe {
            CStr::from_ptr(outbuf.as_ptr() as *mut i8)
        }.to_string_lossy().into_owned();

        Ok(rusage)
    }
    else {
        Err(Error::last_os_error())
    }
}

// Takes an rusage string and builds a hash of metric: value.
// This function is complete trash as iterators are HARD.
fn rusage_to_hashmap(
    jid: i32,
    rusage: &str,
) -> MetricsHash {
    // Create a hashmap to collect our metrics in.
    let mut hash: MetricsHash = HashMap::new();

    // Split up the rusage CSV
    let metrics: Vec<_> = rusage.split(',').collect();

    // Process each metric.
    for metric in metrics {
        // Split each metric into name and value
        let arr: Vec<_> = metric.split('=').collect();

        // Finally add to the hash.
        let name = arr[0].to_string();
        let value: i64 = arr[1].parse().unwrap();

        hash.insert(name, value);
    }

    hash.insert("jid".to_string(), i64::from(jid));

    hash
}

// Processes the MetricsHash setting the appripriate time series.
fn process_metrics_hash(name: &str, metrics: &MetricsHash) {
    for (key, value) in metrics {
        match key.as_ref() {
            "coredumpsize" => {
                JAIL_COREDUMPSIZE_BYTES.with_label_values(&[&name]).set(*value);
            },
            "cputime" => {
                let series = JAIL_CPUTIME_SECONDS.with_label_values(&[&name]);
                let inc = *value - series.get();
                series.inc_by(inc);
            },
            "datasize" => {
                JAIL_DATASIZE_BYTES.with_label_values(&[&name]).set(*value);
            },
            "maxproc" => {
                JAIL_MAXPROC.with_label_values(&[&name]).set(*value);
            },
            "memorylocked" => {
                JAIL_MEMORYLOCKED_BYTES.with_label_values(&[&name]).set(*value);
            },
            "memoryuse" => {
                JAIL_MEMORYUSE_BYTES.with_label_values(&[&name]).set(*value);
            },
            "msgqqueued" => {
                JAIL_MSGQQUEUED.with_label_values(&[&name]).set(*value);
            },
            "msgqsize" => {
                JAIL_MSGQSIZE_BYTES.with_label_values(&[&name]).set(*value);
            },
            "nmsgq" => {
                JAIL_NMSGQ.with_label_values(&[&name]).set(*value);
            },
            "nsem" => {
                JAIL_NSEM.with_label_values(&[&name]).set(*value);
            },
            "nsemop" => {
                JAIL_NSEMOP.with_label_values(&[&name]).set(*value);
            },
            "nshm" => {
                JAIL_NSHM.with_label_values(&[&name]).set(*value);
            },
            "nthr" => {
                JAIL_NTHR.with_label_values(&[&name]).set(*value);
            },
            "openfiles" => {
                JAIL_OPENFILES.with_label_values(&[&name]).set(*value);
            },
            "pcpu" => {
                // rctl reports these as whole integers. Get a usage value
                // closer to what Prometheus users expect.
                let pval: f64 = *value as f64 / 100.0;
                JAIL_PCPU_USED.with_label_values(&[&name]).inc_by(pval);
            },
            "pseudoterminals" => {
                JAIL_PSEUDOTERMINALS.with_label_values(&[&name]).set(*value);
            },
            "shmsize" => {
                JAIL_SHMSIZE_BYTES.with_label_values(&[&name]).set(*value);
            },
            "stacksize" => {
                JAIL_STACKSIZE_BYTES.with_label_values(&[&name]).set(*value);
            },
            "swapuse" => {
                JAIL_SWAPUSE_BYTES.with_label_values(&[&name]).set(*value);
            },
            "vmemoryuse" => {
                JAIL_VMEMORYUSE_BYTES.with_label_values(&[&name]).set(*value);
            },
            "wallclock" => {
                let series = JAIL_WALLCLOCK_SECONDS.with_label_values(&[&name]);
                let inc = *value - series.get();
                series.inc_by(inc);
            },
            // jid isn't actually reported by rctl, but we add it into this
            // hash to keep things simpler.
            "jid" => {
                JAIL_ID.with_label_values(&[&name]).set(*value);
            },
            // Intentionally unhandled metrics.
            // These are documented being difficult to observe via rctl(8).
            "readbps" | "writebps" | "readiops" | "writeiops" => {},
            _ => println!("Unrecognised metric: {}", key),
        }
    }
}

fn get_jail_metrics() {
    let mut lastjid = 0;

    // Set JAIL_TOTAL to zero before gathering.
    JAIL_TOTAL.set(0);

    // Loop over jails.
    while lastjid >= 0 {
        let (jid, value) = jail_get(lastjid);

        if jid > 0 {
            let name = match value {
                Some(value) => value,
                None => "".to_string(),
            };

            let rusage = match rctl_get_jail(&name) {
                Ok(res) => res,
                Err(err) => {
                    err.to_string();
                    break;
                },
            };

            // Get a hash of resources based on rusage string.
            let m = rusage_to_hashmap(jid, &rusage);
            process_metrics_hash(&name, &m);

            JAIL_TOTAL.set(JAIL_TOTAL.get() + 1);
        }
        else {
            // Lastjid was never changed and jail_get returned < -1
            // Some error other than not finding jails occurred
            if lastjid == 0 && jid < -1 {
                println!("{:?}", Error::last_os_error());
            }
            // lastjid was changed and jid is -1
            // We successfully interated over jails and none are left.
            else if lastjid != 0 && jid == -1 {

            }
            else {
                println!("No jails found");
            }
        }

        lastjid = jid;
    }
}

fn metrics(_req: Request<Body>) -> Response<Body> {
    get_jail_metrics();
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from(buffer))
        .unwrap()
}

// HTTP request router
fn http_router(req: Request<Body>) -> Response<Body> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            metrics(req)
        },
        _ => {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap()
        },
    }
}

// Used as a validator for the argument parsing.
fn is_ipaddress(s: String) -> Result<(), String> {
    let res = SocketAddr::from_str(&s);
    match res {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("'{}' is not a valid ADDR:PORT string", s)),
    }
}

fn main() {
    let matches = clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(clap::Arg::with_name("WEB_LISTEN_ADDRESS")
             .long("web.listen-address")
             .value_name("[ADDR:PORT]")
             .help("Address on which to expose metrics and web interface.")
             .takes_value(true)
             .default_value("127.0.0.1:9999")
             .validator(is_ipaddress))
        .arg(clap::Arg::with_name("WEB_TELEMETRY_PATH")
             .long("web.telemetry-path")
             .value_name("PATH")
             .help("Path under which to expose metrics.")
             .takes_value(true)
             .default_value("/metrics"))
        .get_matches();

    // This should always be fine, we've already validated it during arg
    // parsing.
    // However, we keep the expect as a last resort.
    let addr: SocketAddr = matches.value_of("WEB_LISTEN_ADDRESS").unwrap()
        .parse().expect("unable to parse socket address");

    let router = || {
        service_fn_ok(http_router)
    };

    let server = Server::bind(&addr)
        .serve(router)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::run(server);
}
