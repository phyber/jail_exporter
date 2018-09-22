//
// jail_exporter
//
// An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//

extern crate env_logger;
extern crate jail_exporter;
extern crate rctl;
extern crate warp;

// Macro using crates.
#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

use std::net::SocketAddr;
use std::process::exit;
use std::str;
use std::str::FromStr;
use warp::{
    Filter,
    http::Response,
};

// The Prometheus exporter.
// lazy_static! uses unsafe code.
lazy_static!{
    static ref EXPORTER: jail_exporter::Metrics = jail_exporter::Metrics::new();
}

// Returns a warp Reply containing the Prometheus Exporter output, or a
// Rejection if things fail for some reason.
fn metrics(_: ()) -> Result<impl warp::Reply, warp::Rejection> {
    debug!("Processing metrics request");

    // Get exporter output
    let output = EXPORTER.export();

    // Create a string from the exporter output, or return a server error if
    // the exporter failed.
    match str::from_utf8(&output) {
        Ok(v) => Ok(Response::builder().body(String::from(v))),
        Err(_) => Err(warp::reject::server_error()),
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
                .env("JAIL_EXPORTER_WEB_LISTEN_ADDRESS")
                .hide_env_values(true)
                .long("web.listen-address")
                .value_name("[ADDR:PORT]")
                .help("Address on which to expose metrics and web interface.")
                .takes_value(true)
                .default_value("127.0.0.1:9452")
                .validator(|v| is_ipaddress(&v)),
        )
        .arg(
            clap::Arg::with_name("WEB_TELEMETRY_PATH")
                .env("JAIL_EXPORTER_WEB_TELEMETRY_PATH")
                .hide_env_values(true)
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
    debug!("web.listen-address: {}", addr);

    // Get the WEB_TELEMETRY_PATH and turn it into an owned string for moving
    // into the route handler below.
    let telemetry_path = matches
        .value_of("WEB_TELEMETRY_PATH")
        .unwrap();
    let telemetry_path = telemetry_path.to_owned();
    debug!("web.telemetry-path: {}", telemetry_path);

    // Telemetry path handler.
    // We cannot use the usual warp path handling, as it requires static &str
    // with sizes known ahead of time. However, we can work around this as
    // suggested by the author here:
    //   https://github.com/seanmonstar/warp/issues/31
    let telemetry = warp::get2()
        .and(warp::path::param::<String>())
        .and_then(move |param: String| {
            // Turn the param into a path we can compare.
            let mut get_path = "/".to_owned();
            get_path.push_str(&param);

            if get_path == telemetry_path {
                Ok(())
            }
            else {
                Err(warp::reject::not_found())
            }
        });

    // If the above evaluates to Ok, then we get the metrics.
    let telemetry = telemetry.and_then(metrics);

    // We only have the single telemetry route for now.
    let routes = telemetry;

    // Create a server to serve our routes.
    let server = warp::serve(routes);

    // Run it!
    info!("Starting HTTP server on {}", addr);
    server.run(addr);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ipaddress_with_port() {
        let addr = "127.0.0.1:9452";
        let res = is_ipaddress(&addr);
        assert!(res.is_ok());
    }

    #[test]
    fn test_is_ipaddress_without_port() {
        let addr = "127.0.0.1";
        let res = is_ipaddress(&addr);
        assert!(res.is_err());
    }

    #[test]
    fn test_ip_address_no_ip() {
        let addr = "random string";
        let res = is_ipaddress(&addr);
        assert!(res.is_err());
    }
}
