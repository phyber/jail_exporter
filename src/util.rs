// Util, a module for functions with no better home.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use crate::errors::ExporterError;
use crate::rctlstate::RctlState;
use log::debug;
use users::Users;

// Checks for the availability of RACCT/RCTL in the kernel.
pub fn is_racct_rctl_available() -> Result<(), ExporterError> {
    debug!("Checking RACCT/RCTL status");

    match RctlState::check() {
        RctlState::Disabled => {
            Err(ExporterError::RctlUnavailable(
                "Present, but disabled; enable using \
                 kern.racct.enable=1 tunable".to_owned()
            ))
        },
        RctlState::Enabled => Ok(()),
        RctlState::Jailed => {
            // This isn't strictly true. Jail exporter should be able to run
            // within a jail, for situations where a user has jails within
            // jails. It is just untested at the moment.
            Err(ExporterError::RctlUnavailable(
                "Jail Exporter cannot run within a jail".to_owned()
            ))
        },
        RctlState::NotPresent => {
            Err(ExporterError::RctlUnavailable(
                "Support not present in kernel; see rctl(8) \
                 for details".to_owned()
            ))
        },
    }
}

// Checks that we're running as root.
pub fn is_running_as_root<U: Users>(users: &mut U) -> Result<(), ExporterError> {
    debug!("Ensuring that we're running as root");

    match users.get_effective_uid() {
        0 => Ok(()),
        _ => Err(ExporterError::NotRunningAsRoot),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use users::mock::{
        Group,
        MockUsers,
        User,
    };
    use users::os::unix::UserExt;

    #[test]
    fn is_running_as_root_ok() {
        let mut users = MockUsers::with_current_uid(0);
        let user = User::new(0, "root", 0).with_home_dir("/root");
        users.add_user(user);
        users.add_group(Group::new(0, "root"));

        let is_root = is_running_as_root(&mut users);

        assert!(is_root.is_ok());
    }

    #[test]
    fn is_running_as_non_root() {
        let mut users = MockUsers::with_current_uid(10000);
        let user = User::new(10000, "ferris", 10000).with_home_dir("/ferris");
        users.add_user(user);
        users.add_group(Group::new(10000, "ferris"));

        let is_root = is_running_as_root(&mut users);

        assert!(is_root.is_err());
    }
}
