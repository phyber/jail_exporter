extern crate libc;

use std::ffi::CStr;
use std::mem::size_of;

// Hardcoded for now to the value of security.jail.param.name on FreeBSD 11.1.
const JAIL_NAME_LEN: usize = 256;

// Calls libc::jail_get to get jail jid and name.
// Contains unsafe code.
pub fn get(jid: i32) -> (i32, Option<String>) {
    // Storage for the returned jail name
    let mut value: Vec<u8> = vec![0; JAIL_NAME_LEN];

    // Prepare jail_get parameters.
    let mut iov = vec![
        libc::iovec{
            iov_base: b"lastjid\0" as *const _ as *mut _,
            iov_len:  b"lastjid\0".len(),
        },
        libc::iovec{
            iov_base: &jid as *const _ as *mut _,
            iov_len:  size_of::<i32>(),
        },
        libc::iovec{
            iov_base: b"name\0" as *const _ as *mut _,
            iov_len:  b"name\0".len(),
        },
        libc::iovec{
            iov_base: value.as_mut_ptr() as *mut _,
            iov_len:  JAIL_NAME_LEN,
        },
    ];

    // Execute jail_get with the above parameters
    let jid = unsafe {
        libc::jail_get(
            iov[..].as_mut_ptr() as *mut libc::iovec,
            iov.len() as u32,
            libc::JAIL_DYING,
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
