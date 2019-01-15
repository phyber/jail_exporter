//
// jail_exporter
//
// An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//
#![forbid(unsafe_code)]
use clap::{
    crate_authors,
    crate_description,
    crate_name,
    crate_version,
    ArgMatches,
};
use log::{
    debug,
};
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;
use users;

mod httpd;

// Used as a validator for the argument parsing.
fn is_ipaddress(s: &str) -> Result<(), String> {
    let res = SocketAddr::from_str(&s);
    match res {
        Ok(_)  => Ok(()),
        Err(_) => Err(format!("'{}' is not a valid ADDR:PORT string", s)),
    }
}

// Checks that we're running as root.
fn is_running_as_root() -> bool {
    debug!("Ensuring that we're running as root");

    let uid = users::get_effective_uid();

    match uid {
        0 => true,
        _ => {
            eprintln!("Error: jail_exporter must be run as root");
            false
        },
    }
}

// Checks for the availability of RACCT/RCTL in the kernel.
fn is_racct_rctl_available() -> bool {
    debug!("Checking RACCT/RCTL status");

    match rctl::State::check() {
        rctl::State::Disabled => {
            eprintln!(
                "Error: RACCT/RCTL present, but disabled; enable using \
                 kern.racct.enable=1 tunable"
            );
            false
        },
        rctl::State::Enabled => true,
        rctl::State::Jailed => {
            eprintln!("Error: RACCT/RCTL: Jail Exporter cannot run within a \
                       jail");
            false
        },
        rctl::State::NotPresent => {
            eprintln!(
                "Error: RACCT/RCTL support not present in kernel; see rctl(8) \
                 for details"
            );
            false
        },
    }
}

// Parses the command line arguments and returns the matches.
fn parse_args<'a>() -> ArgMatches<'a> {
    debug!("Parsing command line arguments");

    clap::App::new(crate_name!())
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
        .get_matches()
}

fn main() {
    env_logger::init();

    // Check that we're running as root.
    if !is_running_as_root() {
        exit(1);
    }

    // Check if RACCT/RCTL is available and if it's not, exit.
    if !is_racct_rctl_available() {
        exit(1);
    }

    // Parse the commandline arguments.
    let matches = parse_args();

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

    httpd::run(&addr, telemetry_path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_with_port() {
        let addr = "127.0.0.1:9452";
        let res = is_ipaddress(&addr);
        assert!(res.is_ok());
    }

    #[test]
    fn test_ipv6_with_port() {
        let addr = "[::1]:9452";
        let res = is_ipaddress(&addr);
        assert!(res.is_ok());
    }

    #[test]
    fn test_ipv4_without_port() {
        let addr = "127.0.0.1";
        let res = is_ipaddress(&addr);
        assert!(res.is_err());
    }

    #[test]
    fn test_ipv6_without_port() {
        let addr = "[::1]";
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
