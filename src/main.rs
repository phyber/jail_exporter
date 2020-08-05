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

#[macro_use]
mod macros;

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

#[actix_rt::main]
async fn main() -> Result<(), ExporterError> {
    env_logger::init();

    // Check that we're running as root.
    is_running_as_root(&mut UsersCache::new())?;

    // Check if RACCT/RCTL is available and if it's not, exit.
    is_racct_rctl_available()?;

    // Parse the commandline arguments.
    let matches = cli::parse_args();

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
    let bind_address = matches.value_of("WEB_LISTEN_ADDRESS").ok_or(
        ExporterError::ArgNotSet("web.listen-address".to_owned())
    )?.to_owned();
    debug!("web.listen-address: {}", bind_address);

    // Get the WEB_TELEMETRY_PATH and turn it into an owned string for moving
    // into the httpd::Server below.
    // We shouldn't hit the error conditions here after the validation of the
    // CLI arguments passed.
    let telemetry_path = matches.value_of("WEB_TELEMETRY_PATH").ok_or(
        ExporterError::ArgNotSet("web.telemetry-path".to_owned())
    )?.to_owned();
    debug!("web.telemetry-path: {}", telemetry_path);

    let exporter = Box::new(Exporter::new());

    // Configure and run the http server.
    httpd::Server::new()
        .bind_address(bind_address)
        .telemetry_path(telemetry_path)
        .run(exporter).await?;

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
