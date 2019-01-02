//
// jail_exporter
//
// An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//
use actix_web::{
    http,
    server,
    App,
    HttpResponse,
    Path,
};
use clap::{
    crate_authors,
    crate_description,
    crate_name,
    crate_version,
};
use lazy_static::lazy_static;
use log::{
    debug,
    info,
};
use std::net::SocketAddr;
use std::process::exit;
use std::str;
use std::str::FromStr;

// The Prometheus exporter.
// lazy_static! uses unsafe code.
lazy_static! {
    static ref EXPORTER: jail_exporter::Metrics = jail_exporter::Metrics::new();
}

// Returns a warp Reply containing the Prometheus Exporter output, or a
// Rejection if things fail for some reason.
fn metrics(_info: Path<()>) -> HttpResponse {
    debug!("Processing metrics request");

    // Get exporter output
    let output = EXPORTER.export();

    // Send it out
    HttpResponse::Ok()
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(output)
}

// Used as a validator for the argument parsing.
fn is_ipaddress(s: &str) -> Result<(), String> {
    let res = SocketAddr::from_str(&s);
    match res {
        Ok(_)  => Ok(()),
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
        rctl::State::Jailed => {
            eprintln!("RACCT/RCTL: Jail Exporter cannot run within a jail");
            false
        },
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
    // Unwrap here should be safe since we provide clap with a default value.
    let telemetry_path = matches.value_of("WEB_TELEMETRY_PATH").unwrap();
    let telemetry_path = telemetry_path.to_owned();
    debug!("web.telemetry-path: {}", telemetry_path);

    // Route handlers
    let app = move || App::new()
        .route(&telemetry_path, http::Method::GET, metrics);

    // Create the server
    let server = match server::new(app).bind(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Couldn't bind to {}: {}", addr, e);
            exit(1);
        },
    };

    // Run it!
    info!("Starting HTTP server on {}", addr);
    server.run();
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
