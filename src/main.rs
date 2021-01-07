//!
//! jail_exporter
//!
//! An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//!
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use log::debug;
use users::{
    Users,
    UsersCache,
};

mod cli;
mod errors;
mod exporter;
mod file;
mod httpd;

use errors::ExporterError;
use exporter::Exporter;
use file::FileExporter;

#[cfg(feature = "bcrypt_cmd")]
use dialoguer::Password;

#[cfg(feature = "auth")]
use httpd::auth::BasicAuthConfig;

#[cfg(feature = "bcrypt_cmd")]
use rand::{
    distributions::Alphanumeric,
    thread_rng,
    Rng,
};

#[macro_use]
mod macros;

#[cfg(feature = "rc_script")]
const RC_SCRIPT: &str = include_str!("../rc.d/jail_exporter.in");

// Checks for the availability of RACCT/RCTL in the kernel.
fn is_racct_rctl_available() -> Result<(), ExporterError> {
    debug!("Checking RACCT/RCTL status");

    match rctl::State::check() {
        rctl::State::Disabled => {
            Err(ExporterError::RctlUnavailable(
                "Present, but disabled; enable using \
                 kern.racct.enable=1 tunable".to_owned()
            ))
        },
        rctl::State::Enabled => Ok(()),
        rctl::State::Jailed => {
            // This isn't strictly true. Jail exporter should be able to run
            // within a jail, for situations where a user has jails within
            // jails. It is just untested at the moment.
            Err(ExporterError::RctlUnavailable(
                "Jail Exporter cannot run within a jail".to_owned()
            ))
        },
        rctl::State::NotPresent => {
            Err(ExporterError::RctlUnavailable(
                "Support not present in kernel; see rctl(8) \
                 for details".to_owned()
            ))
        },
    }
}

// Checks that we're running as root.
fn is_running_as_root<U: Users>(users: &mut U) -> Result<(), ExporterError> {
    debug!("Ensuring that we're running as root");

    match users.get_effective_uid() {
        0 => Ok(()),
        _ => Err(ExporterError::NotRunningAsRoot),
    }
}

#[cfg(feature = "bcrypt_cmd")]
// Handles hashing and outputting bcrypted passwords for the bcrypt sub
// command.
fn bcrypt_cmd(matches: &clap::ArgMatches) -> Result<(), ExporterError> {
    // Cost argument is validated and has a default, we can unwrap right
    // away.
    let cost: u32 = matches.value_of("COST")
        .unwrap()
        .parse()
        .unwrap();
    let random = matches.is_present("RANDOM");

    // Password argument is required, unwrap is safe.
    let password = match matches.value_of("PASSWORD") {
        Some(password) => password.into(),
        None           => {
            if random {
                // length was validated by the CLI, we should be safe to
                // unwrap and parse to usize here.
                let length: usize = matches.value_of("LENGTH")
                    .unwrap()
                    .parse()
                    .unwrap();

                thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(length)
                    .map(char::from)
                    .collect()
            }
            else {
                Password::new()
                    .with_prompt("Password")
                    .with_confirmation(
                        "Confirm password",
                        "Password mismatch",
                    )
                    .interact()?
            }
        },
    };

    let hash = bcrypt::hash(&password, cost)?;

    if random {
        println!("Password: {}", password);
    }

    println!("Hash: {}", hash);

    Ok(())
}

#[cfg(feature = "rc_script")]
fn output_rc_script() {
    debug!("Dumping rc(8) script to stdout");

    // The script we included is the one that we use for the ports tree, so
    // we need to replace %%PREFIX%% with a reasonable prefix.
    let output = RC_SCRIPT.replace("%%PREFIX%%", "/usr/local");

    println!("{}", output);
}

#[actix_web::main]
async fn main() -> Result<(), ExporterError> {
    // We do as much as we can without checking if we're running as root.
    env_logger::init();

    // Parse the commandline arguments.
    let matches = cli::parse_args();

    #[cfg(feature = "rc_script")]
    // If we have been asked to dump the rc(8) script, do that, and exit.
    if matches.is_present("RC_SCRIPT") {
        output_rc_script();

        ::std::process::exit(0);
    }

    #[cfg(feature = "bcrypt_cmd")]
    // If we have the auth feature, we can bcrypt passwords for the user.
    if let Some(subcmd) = matches.subcommand_matches("bcrypt") {
        bcrypt_cmd(&subcmd)?;

        ::std::process::exit(0);
    }

    // Root is required beyond this point.
    // Check that we're running as root.
    is_running_as_root(&mut UsersCache::new())?;

    // Check if RACCT/RCTL is available and if it's not, exit.
    is_racct_rctl_available()?;

    // If an output file was specified, we do that. We will never launch the
    // HTTPd when we're passed an OUTPUT_FILE_PATH.
    if let Some(output_path) = matches.value_of("OUTPUT_FILE_PATH") {
        debug!("output.file-path: {}", output_path);

        let exporter = FileExporter::new(output_path);

        return exporter.export();
    }

    // Get the bind_address for the httpd::Server below.
    // We shouldn't hit the error conditions here after the validation of the
    // CLI arguments passed.
    //let bind_address = matches.value_of("WEB_LISTEN_ADDRESS").ok_or(
    //    ExporterError::ArgNotSet("web.listen-address".to_owned())
    //)?.to_owned();
    let bind_address = matches.value_of("WEB_LISTEN_ADDRESS").ok_or_else(|| {
        ExporterError::ArgNotSet("web.listen-address".to_owned())
    })?.to_owned();
    debug!("web.listen-address: {}", bind_address);

    // Get the WEB_TELEMETRY_PATH and turn it into an owned string for moving
    // into the httpd::Server below.
    // We shouldn't hit the error conditions here after the validation of the
    // CLI arguments passed.
    let telemetry_path = matches.value_of("WEB_TELEMETRY_PATH").ok_or_else(|| {
        ExporterError::ArgNotSet("web.telemetry-path".to_owned())
    })?.to_owned();
    debug!("web.telemetry-path: {}", telemetry_path);

    // Start configuring HTTP server.
    // unused_mut here silences a warning if the crate is compiled without auth
    // support.
    #[allow(unused_mut)]
    let mut server = httpd::Server::new()
        .bind_address(bind_address)
        .telemetry_path(telemetry_path);

    #[cfg(feature = "auth")]
    // Get and set the username and password for HTTP Basic Auth
    {
        if let Some(path) = matches.value_of("WEB_AUTH_CONFIG") {
            let config = BasicAuthConfig::from_yaml(&path)?;

            server = server.auth_config(config);
        }
    }

    let exporter = Box::new(Exporter::new());
    server.run(exporter).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

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

        let is_root = is_running_as_root(&mut users).unwrap();
        let ok = ();

        assert_eq!(is_root, ok);
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

        assert!(is_root.is_err());
    }
}
