use super::*;

/////////////////////////////////////////////////////////////////////////////////
// Resolver
//
// Windows uses the system resolver; other native targets use a built-in minimal DNS client

cfg_if! {

    /////////////////////////////////////////////////////////////////////////////
    // WASM (unsupported)

    if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
        mod wasm;
        pub use wasm::*;
    }

    /////////////////////////////////////////////////////////////////////////////
    // Non-Windows

    else if #[cfg(not(target_os = "windows"))] {
        pub(crate) mod non_windows;
        pub use non_windows::*;
    }

    /////////////////////////////////////////////////////////////////////////////
    // Windows

    else {
        mod windows;
        pub use windows::*;
    }

}

/// Error returned by DNS resolution operations.
#[derive(Debug, Clone, Eq, PartialEq, ThisError)]
pub enum ResolverError {
    /// Resolution failed; the string carries a backend-specific description.
    #[error("Generic resolver error: {0}")]
    Generic(String),
}

/// Reverse-lookup name for `ip` (`in-addr.arpa` / `ip6.arpa`), no trailing dot
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[must_use]
pub(crate) fn reverse_name(ip: IpAddr) -> String {
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
