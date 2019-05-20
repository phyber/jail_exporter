//!
//! jail_exporter
//!
//! An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//!
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use clap::{
    crate_authors,
    crate_description,
    crate_name,
    crate_version,
};
use log::debug;
use std::net::SocketAddr;
use std::str::FromStr;
use users::{
    Users,
    UsersCache,
};

mod errors;
use errors::Error;
mod httpd;

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

// Checks that we're running as root.
fn is_running_as_root<U: Users>(users: &mut U) -> Result<(), Error> {
    debug!("Ensuring that we're running as root");

    match users.get_effective_uid() {
        0 => Ok(()),
        _ => Err(Error::NotRunningAsRoot),
    }
}

// Used as a validator for the argument parsing.
fn is_valid_socket_addr(s: String) -> Result<(), String> {
    debug!("Ensuring that web.listen-address is valid");

    match SocketAddr::from_str(&s) {
        Ok(_)  => Ok(()),
        Err(_) => Err(format!("'{}' is not a valid ADDR:PORT string", s)),
    }
}

// Checks that the telemetry_path is valid.
// This check is extremely basic, and there may still be invalid paths that
// could be passed.
fn is_valid_telemetry_path(s: String) -> Result<(), String> {
    debug!("Ensuring that web.telemetry-path is valid");

    // Ensure s isn't empty.
    if s.is_empty() {
        return Err("path must not be empty".to_owned());
    }

    // Ensure that s starts with /
    if !s.starts_with('/') {
        return Err("path must start with /".to_owned());
    }

    // Ensure that s isn't literally /
    if s == "/" {
        return Err("path must not be /".to_owned());
    }

    Ok(())
}

// Create a clap app
fn create_app<'a, 'b>() -> clap::App<'a, 'b> {
    debug!("Creating clap app");

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
                .validator(is_valid_socket_addr)
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
                .validator(is_valid_telemetry_path)
        )
}

// Parses the command line arguments and returns the matches.
fn parse_args<'a>() -> clap::ArgMatches<'a> {
    debug!("Parsing command line arguments");

    create_app().get_matches()
}

fn main() -> Result<(), Error> {
    env_logger::init();

    // Check that we're running as root.
    is_running_as_root(&mut UsersCache::new())?;

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
        .bind_address(bind_address)
        .telemetry_path(telemetry_path)
        .run()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use pretty_assertions::assert_eq;
    use std::env;
    use std::panic;
    use std::sync::Mutex;

    lazy_static! {
        // Used during env_tests
        static ref LOCK: Mutex<i8> = Mutex::new(0);
    }

    // Wraps setting and unsetting of environment variables
    fn env_test<T>(key: &str, var: &str, test: T) -> ()
    where T: FnOnce() -> () + panic::UnwindSafe {
        // This ensures that only one test can be manipulating the environment
        // at a time.
        let _locked = LOCK.lock().unwrap();

        env::set_var(key, var);

        let result = panic::catch_unwind(|| {
            test()
        });

        env::remove_var(key);

        assert!(result.is_ok())
    }

    #[test]
    fn default_web_listen_address() {
        let argv = vec!["jail_exporter"];
        let matches = create_app().get_matches_from(argv);
        let listen_address = matches.value_of("WEB_LISTEN_ADDRESS");

        assert_eq!(listen_address, Some("127.0.0.1:9452"));
    }

    #[test]
    fn default_web_telemetry_path() {
        let argv = vec!["jail_exporter"];
        let matches = create_app().get_matches_from(argv);
        let telemetry_path = matches.value_of("WEB_TELEMETRY_PATH");

        assert_eq!(telemetry_path, Some("/metrics"));
    }

    #[test]
    fn cli_set_web_listen_address() {
        let argv = vec![
            "jail_exporter",
            "--web.listen-address=127.0.1.2:9452",
        ];

        let matches = create_app().get_matches_from(argv);
        let listen_address = matches.value_of("WEB_LISTEN_ADDRESS");

        assert_eq!(listen_address, Some("127.0.1.2:9452"));
    }

    #[test]
    fn cli_override_env_web_listen_address() {
        env_test("JAIL_EXPORTER_WEB_LISTEN_ADDRESS", "127.0.1.2:9452", || {
            let argv = vec![
                "jail_exporter",
                "--web.listen-address=127.0.1.3:9452",
            ];

            let matches = create_app().get_matches_from(argv);
            let listen_address = matches.value_of("WEB_LISTEN_ADDRESS");

            assert_eq!(listen_address, Some("127.0.1.3:9452"));
        });
    }

    #[test]
    fn cli_override_env_web_telemetry_path() {
        env_test("JAIL_EXPORTER_WEB_TELEMETRY_PATH", "/envvar", || {
            let argv = vec![
                "jail_exporter",
                "--web.telemetry-path=/clioverride",
            ];

            let matches = create_app().get_matches_from(argv);
            let listen_address = matches.value_of("WEB_TELEMETRY_PATH");

            assert_eq!(listen_address, Some("/clioverride"));
        });
    }

    #[test]
    fn cli_set_web_telemetry_path() {
        let argv = vec![
            "jail_exporter",
            "--web.telemetry-path=/test",
        ];

        let matches = create_app().get_matches_from(argv);
        let telemetry_path = matches.value_of("WEB_TELEMETRY_PATH");

        assert_eq!(telemetry_path, Some("/test"));
    }

    #[test]
    fn env_set_web_listen_address() {
        env_test("JAIL_EXPORTER_WEB_LISTEN_ADDRESS", "127.0.1.2:9452", || {
            let argv = vec!["jail_exporter"];
            let matches = create_app().get_matches_from(argv);
            let listen_address = matches.value_of("WEB_LISTEN_ADDRESS");

            assert_eq!(listen_address, Some("127.0.1.2:9452"));
        });
    }

    #[test]
    fn env_set_web_telemetry_path() {
        env_test("JAIL_EXPORTER_WEB_TELEMETRY_PATH", "/test", || {
            let argv = vec!["jail_exporter"];
            let matches = create_app().get_matches_from(argv);
            let telemetry_path = matches.value_of("WEB_TELEMETRY_PATH");

            assert_eq!(telemetry_path, Some("/test"));
        });
    }

    #[test]
    fn is_running_as_root_ok() {
        use users::mock::{
            Group,
            MockUsers,
            User,
        };
        use users::os::unix::UserExt;

        let mut users = MockUsers::with_current_uid(0);
        let user = User::new(0, "root", 0).with_home_dir("/root");
        users.add_user(user);
        users.add_group(Group::new(0, "root"));

        let is_root = is_running_as_root(&mut users);
        let ok = ();

        assert!(is_root.is_ok(), ok);
    }

    #[test]
    fn is_running_as_non_root() {
        use users::mock::{
            Group,
            MockUsers,
            User,
        };
        use users::os::unix::UserExt;

        let mut users = MockUsers::with_current_uid(10000);
        let user = User::new(10000, "ferris", 10000).with_home_dir("/ferris");
        users.add_user(user);
        users.add_group(Group::new(10000, "ferris"));

        let is_root = is_running_as_root(&mut users);
        let err = Error::NotRunningAsRoot;

        assert!(is_root.is_err(), err);
    }

    #[test]
    fn is_valid_socket_addr_ipv4_with_port() {
        let res = is_valid_socket_addr("127.0.0.1:9452".into());
        assert!(res.is_ok());
    }

    #[test]
    fn is_valid_socket_addr_ipv6_with_port() {
        let res = is_valid_socket_addr("[::1]:9452".into());
        assert!(res.is_ok());
    }

    #[test]
    fn is_valid_socket_addr_ipv4_without_port() {
        let res = is_valid_socket_addr("127.0.0.1".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_socket_addr_ipv6_without_port() {
        let res = is_valid_socket_addr("[::1]".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_socket_addr_no_ip() {
        let res = is_valid_socket_addr("random string".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_telemetry_path_slash() {
        let res = is_valid_telemetry_path("/".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_telemetry_path_empty() {
        let res = is_valid_telemetry_path("".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_telemetry_path_relative() {
        let res = is_valid_telemetry_path("metrics".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_telemetry_path_valid() {
        let res = is_valid_telemetry_path("/metrics".into());
        assert!(res.is_ok());
    }
}
