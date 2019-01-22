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
use std::str::FromStr;
use users;

mod errors;
use errors::Error;
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
fn is_running_as_root() -> Result<(), Error> {
    debug!("Ensuring that we're running as root");

    match users::get_effective_uid() {
        0 => Ok(()),
        _ => Err(Error::NotRunningAsRoot),
    }
}

// Checks for the availability of RACCT/RCTL in the kernel.
fn is_racct_rctl_available() -> Result<(), Error> {
    debug!("Checking RACCT/RCTL status");

    match rctl::State::check() {
        rctl::State::Disabled => {
            Err(Error::RctlUnavailable(
                "Present, but disabled; enable using \
                 kern.racct.enable=1 tunable".to_owned()
            ))
        },
        rctl::State::Enabled => Ok(()),
        rctl::State::Jailed => {
            // This isn't strictly true. Jail exporter should be able to run
            // within a jail, for situations where a user has jails within
            // jails. It is just untested at the moment.
            Err(Error::RctlUnavailable(
                "Jail Exporter cannot run within a jail".to_owned()
            ))
        },
        rctl::State::NotPresent => {
            Err(Error::RctlUnavailable(
                "Support not present in kernel; see rctl(8) \
                 for details".to_owned()
            ))
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

fn main() -> Result<(), Error> {
    env_logger::init();

    // Check that we're running as root.
    is_running_as_root()?;

    // Check if RACCT/RCTL is available and if it's not, exit.
    is_racct_rctl_available()?;

    // Parse the commandline arguments.
    let matches = parse_args();

    // Get the bind_address for the httpd::Server below.
    // We shouldn't hit the error conditions here after the validation of the
    // CLI arguments passed.
    let bind_address = match matches.value_of("WEB_LISTEN_ADDRESS") {
        None    => Err(Error::ArgNotSet("web.listen-address".to_owned())),
        Some(s) => Ok(s.to_owned()),
    }?;
    debug!("web.listen-address: {}", bind_address);

    // Get the WEB_TELEMETRY_PATH and turn it into an owned string for moving
    // into the httpd::Server below.
    // We shouldn't hit the error conditions here after the validation of the
    // CLI arguments passed.
    let telemetry_path = match matches.value_of("WEB_TELEMETRY_PATH") {
        None    => Err(Error::ArgNotSet("web.telemetry-path".to_owned())),
        Some(s) => Ok(s.to_owned()),
    }?;
    debug!("web.telemetry-path: {}", telemetry_path);

    // Configure and run the http server.
    httpd::Server::new()
        .bind_address(bind_address)?
        .telemetry_path(telemetry_path)
        .run()?;

    Ok(())
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
