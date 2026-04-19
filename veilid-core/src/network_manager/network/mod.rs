mod platform_network;
mod platform_protocol_network_connection;

cfg_if! {
    if #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))] {
        mod native;
    }
    else if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
        mod wasm;
    }
    else {
        compile_error!("No network implementation for this platform!");
    }
}

use super::*;

pub use platform_network::*;
pub use platform_protocol_network_connection::*;
