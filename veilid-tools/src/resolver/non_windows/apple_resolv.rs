//! Apple system nameservers via libresolv, which reads the configd view the sandbox permits.
//!
//! The symbols are bound at runtime so nothing that links this crate needs `-lresolv`; a static
//! archive cannot carry a link requirement, so an Xcode consumer would otherwise have to add it.

use super::*;
use config::DNS_PORT;
use std::ffi::{c_void, CStr};
use std::os::raw::c_int;

/// `struct __res_state` is 552 bytes on 64-bit Apple (resolv.h); opaque here and over-allocated
#[repr(C, align(8))]
struct ResState([u8; 1024]);

/// `union res_sockaddr_union` (resolv.h): a sockaddr_in or sockaddr_in6 in a 128-byte slot
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct ResSockaddrUnion([u8; 128]);

const MAX_SERVERS: usize = 8;
/// The install name every binary linked against libresolv records, so dyld always has it
const LIBRESOLV_PATH: &CStr = c"/usr/lib/libresolv.9.dylib";

// resolv.h maps the unprefixed names to these
type NInitFn = unsafe extern "C" fn(*mut ResState) -> c_int;
type GetServersFn = unsafe extern "C" fn(*mut ResState, *mut ResSockaddrUnion, c_int) -> c_int;
type NDestroyFn = unsafe extern "C" fn(*mut ResState);

struct ResolvFns {
    ninit: NInitFn,
    getservers: GetServersFn,
    ndestroy: NDestroyFn,
}

static RESOLV: LazyLock<Option<ResolvFns>> = LazyLock::new(load);

/// Nameservers the system resolver would use; `None` when libresolv reports none
#[must_use]
pub(crate) fn system_name_servers() -> Option<Vec<SocketAddr>> {
    let mut state = ResStateGuard::init()?;
    let servers = state.servers();
    (!servers.is_empty()).then_some(servers)
}

struct ResStateGuard {
    state: Box<ResState>,
    fns: &'static ResolvFns,
}

impl ResStateGuard {
    fn init() -> Option<Self> {
        let fns = RESOLV.as_ref()?;
        let mut state = Box::new(ResState([0u8; 1024]));
        // SAFETY: state is a live, zeroed, 8-aligned 1024-byte buffer, larger than the 552-byte
        // struct __res_state, and exclusively borrowed for the call
        let rc = unsafe { (fns.ninit)(&mut *state as *mut ResState) };
        (rc == 0).then_some(Self { state, fns })
    }

    fn servers(&mut self) -> Vec<SocketAddr> {
        let mut set = [ResSockaddrUnion([0u8; 128]); MAX_SERVERS];
        // SAFETY: the state was initialized by a successful ninit and is not yet destroyed; set is
        // a writable array of MAX_SERVERS unions and cnt matches its length
        let count = unsafe {
            (self.fns.getservers)(
                &mut *self.state as *mut ResState,
                set.as_mut_ptr(),
                MAX_SERVERS as c_int,
            )
        };
        set.iter()
            .take(count.max(0) as usize)
            .filter_map(parse_sockaddr_union)
            .collect()
    }
}

impl Drop for ResStateGuard {
    fn drop(&mut self) {
        // SAFETY: called once, on a state a successful ninit initialized, and the buffer outlives
        // the call
        unsafe { (self.fns.ndestroy)(&mut *self.state as *mut ResState) };
    }
}

/// Decode the sockaddr bytes rather than casting to libc structs
fn parse_sockaddr_union(u: &ResSockaddrUnion) -> Option<SocketAddr> {
    let b = &u.0;
    let port = match u16::from_be_bytes([b[2], b[3]]) {
        0 => DNS_PORT,
        port => port,
    };
    match c_int::from(b[1]) {
        libc::AF_INET => {
            let addr = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            Some(SocketAddr::V4(SocketAddrV4::new(addr, port)))
        }
        libc::AF_INET6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[8..24]);
            let scope_id = u32::from_ne_bytes([b[24], b[25], b[26], b[27]]);
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                scope_id,
            )))
        }
        _ => None,
    }
}

fn load() -> Option<ResolvFns> {
    // SAFETY: an absolute NUL-terminated system path; the handle is checked for null and, since it
    // is never closed, every symbol resolved from it stays valid
    let handle =
        unsafe { libc::dlopen(LIBRESOLV_PATH.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return None;
    }
    Some(ResolvFns {
        // SAFETY: symbol() yields a live non-null address for res_9_ninit, cast to its prototype
        // from resolv.h
        ninit: unsafe {
            std::mem::transmute::<*mut c_void, NInitFn>(symbol(handle, c"res_9_ninit")?)
        },
        // SAFETY: symbol() yields a live non-null address for res_9_getservers, cast to its
        // prototype from resolv.h
        getservers: unsafe {
            std::mem::transmute::<*mut c_void, GetServersFn>(symbol(handle, c"res_9_getservers")?)
        },
        // SAFETY: symbol() yields a live non-null address for res_9_ndestroy, cast to its prototype
        // from resolv.h
        ndestroy: unsafe {
            std::mem::transmute::<*mut c_void, NDestroyFn>(symbol(handle, c"res_9_ndestroy")?)
        },
    })
}

fn symbol(handle: *mut c_void, name: &CStr) -> Option<*mut c_void> {
    // SAFETY: handle is a live dlopen result and name is a NUL-terminated literal
    let sym = unsafe { libc::dlsym(handle, name.as_ptr()) };
    (!sym.is_null()).then_some(sym)
}
