//! Reverse DNS for the bootstrap record tool, through the platform's own resolver: libc
//! `getnameinfo` on unix, `DnsQuery_UTF8` on Windows (the DNS Client service, so its configured
//! servers and DoH apply). The calls block, so they run on the blocking pool. Items carry `#[cfg]`
//! attributes rather than a `cfg_if!` so the unsafe census sees every block.

#![allow(
    unsafe_code,
    reason = "platform resolver calls; every block carries a SAFETY line"
)]

use crate::tools::*;
use std::net::IpAddr;
use veilid_core::tools::blocking_wrapper;

#[cfg(unix)]
const NI_MAXHOST: usize = 1025;

/// The PTR name of `ip_addr` without its trailing dot; an address with none is an error
#[cfg(unix)]
pub async fn ptr_lookup(ip_addr: IpAddr) -> EyreResult<String> {
    use std::ffi::CStr;
    use std::net::SocketAddr;
    use std::os::raw::c_char;

    blocking_wrapper(move || {
        let addr = socket2::SockAddr::from(SocketAddr::new(ip_addr, 0));
        let mut host = vec![0 as c_char; NI_MAXHOST];
        // SAFETY: addr is a valid sockaddr of the stated length and host is a writable buffer
        // of the stated length; NI_NAMEREQD fails rather than returning the address as text
        let rc = unsafe {
            libc::getnameinfo(
                addr.as_ptr() as *const libc::sockaddr,
                addr.len(),
                host.as_mut_ptr(),
                NI_MAXHOST as _,
                std::ptr::null_mut(),
                0,
                libc::NI_NAMEREQD,
            )
        };
        if rc != 0 {
            // SAFETY: gai_strerror returns a pointer to a static NUL-terminated string
            let message = unsafe { CStr::from_ptr(libc::gai_strerror(rc)) }.to_string_lossy();
            bail!("{}", message);
        }
        // SAFETY: getnameinfo NUL-terminates host on success
        let name = unsafe { CStr::from_ptr(host.as_ptr()) }
            .to_str()
            .map_err(|_| eyre!("non-utf8 hostname"))?;
        Ok(name.trim_end_matches('.').to_owned())
    })
    .await
}

/// The PTR name of `ip_addr` without its trailing dot; an address with none is an error
#[cfg(windows)]
pub async fn ptr_lookup(ip_addr: IpAddr) -> EyreResult<String> {
    use ::windows::core::{PCSTR, PSTR};
    use ::windows::Win32::NetworkManagement::Dns::{
        DnsFree, DnsFreeRecordList, DnsQuery_UTF8, DNS_QUERY_STANDARD, DNS_RECORDA, DNS_TYPE_PTR,
    };
    use core::ffi::c_void;
    use std::ffi::{CStr, CString};

    let host = CString::new(reverse_name(ip_addr)).map_err(|_| eyre!("interior nul"))?;
    // SAFETY: host is NUL-terminated and outlives the call; the record list DnsQuery_UTF8 returns
    // is walked through its own pNext links and freed exactly once with DnsFree on every path
    blocking_wrapper(move || unsafe {
        let mut p_query_results: *mut DNS_RECORDA = core::ptr::null_mut();
        DnsQuery_UTF8(
            PCSTR::from_raw(host.as_bytes_with_nul().as_ptr()),
            DNS_TYPE_PTR,
            DNS_QUERY_STANDARD,
            None,
            &mut p_query_results as *mut *mut DNS_RECORDA,
            None,
        )
        .ok()
        .map_err(|e| eyre!("DnsQuery error {}", e.code().0))?;

        let mut found = None;
        let mut p_record: *const DNS_RECORDA = p_query_results;
        while let Some(record) = p_record.as_ref() {
            if record.wType == DNS_TYPE_PTR.0 {
                let p_name_host: PSTR = record.Data.PTR.pNameHost;
                if !p_name_host.is_null() {
                    if let Ok(name) = CStr::from_ptr(p_name_host.0 as *const i8).to_str() {
                        found = Some(name.trim_end_matches('.').to_owned());
                        break;
                    }
                }
            }
            p_record = record.pNext;
        }
        DnsFree(Some(p_query_results as *const c_void), DnsFreeRecordList);
        found.ok_or_else(|| eyre!("no PTR record"))
    })
    .await
}

/// Reverse-lookup name for `ip` (`in-addr.arpa` / `ip6.arpa`), no trailing dot
#[cfg(windows)]
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let oct = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", oct[3], oct[2], oct[1], oct[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::new();
            for b in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0x0F, b >> 4));
            }
            format!("{}ip6.arpa", s)
        }
    }
}
