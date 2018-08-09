//
// jail_exporter
//
// An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//
#[forbid(unsafe_code)]

extern crate env_logger;
extern crate hyper;
extern crate jail_exporter;
extern crate rctl;

// Macro using crates.
#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

use hyper::header::CONTENT_TYPE;
use hyper::rt::Future;
use hyper::service::service_fn_ok;
use hyper::{
    Body,
    Method,
    Request,
    Response,
    Server,
    StatusCode,
};
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;

lazy_static!{
    static ref EXPORTER: jail_exporter::Metrics = jail_exporter::Metrics::new();
}

fn metrics(_req: &Request<Body>) -> Response<Body> {
    debug!("Processing metrics request");

    let output = EXPORTER.export();

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from(output))
        .unwrap()
}

// HTTP request router
fn http_router(req: &Request<Body>) -> Response<Body> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => metrics(&req),
        _ => {
            debug!("No handler for request found");
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap()
        },
    }
}

// Used as a validator for the argument parsing.
fn is_ipaddress(s: &str) -> Result<(), String> {
    let res = SocketAddr::from_str(&s);
    match res {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("'{}' is not a valid ADDR:PORT string", s)),
    }
}

fn main() {
    env_logger::init();

    // First, check if RACCT/RCTL is available.
    debug!("Checking RACCT/RCTL status");
    let racct_rctl_available = match rctl::State::check() {
        rctl::State::Disabled => {
            eprintln!(
                "RACCT/RCTL present, but disabled; enable using \
                 kern.racct.enable=1 tunable"
            );
            false
        },
        rctl::State::Enabled => true,
        rctl::State::NotPresent => {
            eprintln!(
                "RACCT/RCTL support not present in kernel; see rctl(8) \
                 for details"
            );
            false
        },
    };

    // If it's not available, exit.
    if !racct_rctl_available {
        exit(1);
    }

    debug!("Parsing command line arguments");
    let matches = clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            clap::Arg::with_name("WEB_LISTEN_ADDRESS")
                .long("web.listen-address")
                .value_name("[ADDR:PORT]")
                .help("Address on which to expose metrics and web interface.")
                .takes_value(true)
                .default_value("127.0.0.1:9452")
                .validator(|v| is_ipaddress(&v)),
        )
        .arg(
            clap::Arg::with_name("WEB_TELEMETRY_PATH")
                .long("web.telemetry-path")
                .value_name("PATH")
                .help("Path under which to expose metrics.")
                .takes_value(true)
                .default_value("/metrics"),
        )
        .get_matches();

    // This should always be fine, we've already validated it during arg
    // parsing.
    // However, we keep the expect as a last resort.
    let addr: SocketAddr = matches
        .value_of("WEB_LISTEN_ADDRESS")
        .unwrap()
        .parse()
        .expect("unable to parse socket address");

    let router = || service_fn_ok(|req| http_router(&req));

    info!("Starting HTTP server on {}", addr);
    let server = Server::bind(&addr)
        .serve(router)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::run(server);
}
