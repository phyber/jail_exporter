extern crate libc;

use std::collections::HashMap;
use std::ffi::{
    CStr,
    CString,
};
use std::io::Error;

// MetricsHash stores our Key: Value hashmap
pub type MetricsHash = HashMap<String, i64>;

// Set to the same value as found in rctl.c in FreeBSD 11.1
const RCTL_DEFAULT_BUFSIZE: usize = 128 * 1024;

fn rctl_get_jail(jail_name: &str) -> Result<String, Error> {
    extern "C" {
        fn rctl_get_racct(
            inbufp: *const libc::c_char,
            inbuflen: libc::size_t,
            outbufp: *mut libc::c_char,
            outbuflen: libc::size_t,
        ) -> libc::c_int;
    }

    // Create the filter for this specific jail and take the length of the
    // string.
    let mut filter = "jail:".to_string();
    filter.push_str(jail_name);
    let filterlen = filter.len() + 1;

    // C compatible output buffer.
    let outbuflen: usize = RCTL_DEFAULT_BUFSIZE / 4;
    let mut outbuf: Vec<i8> = vec![0; outbuflen];

    // Get the filter as a C string.
    let cfilter = CString::new(filter).unwrap();

    // Unsafe C call to get the jail resource usage.
    let error = unsafe {
        rctl_get_racct(
            cfilter.as_ptr(),
            filterlen,
            outbuf.as_mut_ptr(),
            outbuflen,
        )
    };

    // If everything went well, convert the return C string in the outbuf back
    // into an easily usable Rust string and return.
    if error == 0 {
        let rusage = unsafe {
            CStr::from_ptr(outbuf.as_ptr() as *mut i8)
        }.to_string_lossy().into_owned();

        Ok(rusage)
    }
    else {
        Err(Error::last_os_error())
    }
}

// Takes an rusage string and builds a hash of metric: value.
// This function is complete trash as iterators are HARD.
fn rusage_to_hashmap(
    jid: i32,
    rusage: &str,
) -> MetricsHash {
    // Create a hashmap to collect our metrics in.
    let mut hash: MetricsHash = HashMap::new();

    // Split up the rusage CSV
    let metrics: Vec<_> = rusage.split(',').collect();

    // Process each metric.
    for metric in metrics {
        // Split each metric into name and value
        let arr: Vec<_> = metric.split('=').collect();

        // Finally add to the hash.
        let name = arr[0].to_string();
        let value: i64 = arr[1].parse().unwrap();

        hash.insert(name, value);
    }

    hash.insert("jid".to_string(), i64::from(jid));

    hash
}

pub fn get_resource_usage(
    jid: i32,
    jail_name: &str
) -> Result<MetricsHash, String> {
    let rusage_str = match rctl_get_jail(&jail_name) {
        Ok(res) => res,
        Err(err) => err.to_string(),
    };

    Ok(rusage_to_hashmap(jid, &rusage_str))
}
