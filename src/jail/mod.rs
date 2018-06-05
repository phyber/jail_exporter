extern crate libc;

use libc::JAIL_DYING;
use libc::{
    iovec,
    jail_get,
};
use std::ffi::CStr;
use std::mem::size_of;

// Hardcoded for now to the value of security.jail.param.name on FreeBSD 11.1.
const JAIL_NAME_LEN: usize = 256;

// jail_get parameter strings
const PARAM_LASTJID: &[u8] = b"lastjid\0";
const PARAM_NAME: &[u8] = b"name\0";

// Calls libc::jail_get to get jail jid and name.
// Contains unsafe code.
pub fn get(jid: i32) -> (i32, Option<String>) {
    // Storage for the returned jail name
    let mut value: Vec<u8> = vec![0; JAIL_NAME_LEN];

    // Prepare jail_get parameters.
    let mut iov = vec![
        iovec{
            iov_base: PARAM_LASTJID as *const _ as *mut _,
            iov_len:  PARAM_LASTJID.len(),
        },
        iovec{
            iov_base: &jid as *const _ as *mut _,
            iov_len:  size_of::<i32>(),
        },
        iovec{
            iov_base: PARAM_NAME as *const _ as *mut _,
            iov_len:  PARAM_NAME.len(),
        },
        iovec{
            iov_base: value.as_mut_ptr() as *mut _,
            iov_len:  JAIL_NAME_LEN,
        },
    ];

    // Execute jail_get with the above parameters
    let jid = unsafe {
        jail_get(
            iov[..].as_mut_ptr() as *mut iovec,
            iov.len() as u32,
            JAIL_DYING,
        )
    };

    // If we found a jail, get its name as a Rust string and return.
    if jid > 0 {
        let name = unsafe {
            CStr::from_ptr(value.as_ptr() as *mut i8)
        }.to_string_lossy().into_owned();

        return (jid, Some(name));
    }

    // We didn't find anything.
    (jid, None)
}
