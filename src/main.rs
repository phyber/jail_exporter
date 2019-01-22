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
    debug!("Ensuring that web.listen-address is valid");

    let res = SocketAddr::from_str(&s);
    match res {
        Ok(_)  => Ok(()),
        Err(_) => Err(format!("'{}' is not a valid ADDR:PORT string", s)),
    }
}

// Checks that we're running as root.
fn is_running_as_root() -> bool {
    debug!("Ensuring that we're running as root");

    match users::get_effective_uid() {
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

// Checks that the telemetry_path is valid.
// This check is extremely basic, and there may still be invalid paths that
// could be passed.
fn is_valid_telemetry_path(s: &str) -> Result<(), String> {
    debug!("Ensuring that web.telemetry-path is valid");

    // Ensure s isn't empty.
    if s.is_empty() {
        return Err("path must not be empty".to_owned());
    }

    // Ensure that s starts with /
    if !s.starts_with("/") {
        return  Err("path must start with /".to_owned());
    }

    // Ensure that s isn't literally /
    if s == "/" {
        return Err("path must not be /".to_owned())
    }

    Ok(())
}

// Parses the command line arguments and returns the matches.
fn parse_args<'a>() -> ArgMatches<'a> {
    debug!("Parsing command line arguments");

    clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .set_term_width(80)
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
                .default_value("/metrics")
                .validator(|v| is_valid_telemetry_path(&v)),
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

    // Configure and run the http server.
    httpd::Server::new()
        .bind_address(addr)
        .telemetry_path(telemetry_path)
        .run();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ipaddress_ipv4_with_port() {
        let addr = "127.0.0.1:9452";
        let res = is_ipaddress(&addr);
        assert!(res.is_ok());
    }

    #[test]
    fn test_is_ipaddress_ipv6_with_port() {
        let addr = "[::1]:9452";
        let res = is_ipaddress(&addr);
        assert!(res.is_ok());
    }

    #[test]
    fn test_is_ipaddress_ipv4_without_port() {
        let addr = "127.0.0.1";
        let res = is_ipaddress(&addr);
        assert!(res.is_err());
    }

    #[test]
    fn test_is_ipaddress_ipv6_without_port() {
        let addr = "[::1]";
        let res = is_ipaddress(&addr);
        assert!(res.is_err());
    }

    #[test]
    fn test_is_ipaddress_no_ip() {
        let addr = "random string";
        let res = is_ipaddress(&addr);
        assert!(res.is_err());
    }

    #[test]
    fn test_is_valid_telemetry_path_slash() {
        let s = "/";
        let res = is_valid_telemetry_path(&s);
        assert!(res.is_err());
    }

    #[test]
    fn test_is_valid_telemetry_path_empty() {
        let s = "";
        let res = is_valid_telemetry_path(&s);
        assert!(res.is_err());
    }

    #[test]
    fn test_is_valid_telemetry_path_relative() {
        let s = "metrics";
        let res = is_valid_telemetry_path(&s);
        assert!(res.is_err());
    }

    #[test]
    fn test_is_valid_telemetry_path_valid() {
        let s = "/metrics";
        let res = is_valid_telemetry_path(&s);
        assert!(res.is_ok());
    }
}
