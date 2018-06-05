extern crate libc;
extern crate sysctl;

use libc::JAIL_DYING;
use libc::{
    iovec,
    jail_get,
};
use std::ffi::CStr;
use std::mem::size_of;

// Default param length if we fail to get one from sysctl.
const DEFAULT_PARAM_LEN: usize = 256;

// jail_get parameter strings
const PARAM_LASTJID: &[u8] = b"lastjid\0";
const PARAM_NAME: &[u8] = b"name\0";

// Attempts to get the real param length from sysctl. If it cannot, it simply
// returns DEFAULT_PARAM_LEN
fn get_param_length(param: &str) -> usize {
    let ctl = format!("security.jail.param.{}", param);
    let val_enum = sysctl::value(&ctl).unwrap();

    if let sysctl::CtlValue::Int(val) = val_enum {
        val as usize
    }
    else {
        DEFAULT_PARAM_LEN
    }
}

// Calls libc::jail_get to get jail jid and name.
// Contains unsafe code.
pub fn get(jid: i32) -> (i32, Option<String>) {
    // Get parameter length from sysctl
    let max_name_len = get_param_length("name");

    // Storage for the returned jail name
    let mut value: Vec<u8> = vec![0; max_name_len];

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
            iov_len:  max_name_len,
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
