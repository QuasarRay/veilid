// Wasm-only in production, but unit-tested on every platform
#[cfg(any(
    all(target_arch = "wasm32", target_os = "unknown"),
    test,
    feature = "test-util"
))]
mod address_family_confirm_logic;
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

#[cfg(any(
    all(target_arch = "wasm32", target_os = "unknown"),
    test,
    feature = "test-util"
))]
pub(crate) use address_family_confirm_logic::*;
pub use platform_network::*;
pub use platform_protocol_network_connection::*;

/// The interface addresses dial info can be built on: all but loopback and link-local.
/// A change outside this set, such as a new link-local address, leaves dial info valid.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn routable_interface_addresses(
    state: &NetworkInterfaceAddressState,
) -> HashSet<Address> {
    state
        .interface_addresses
        .iter()
        .map(|a| Address::from_ip_addr(a.ip()))
        .filter(|addr| addr.is_routable())
        .collect()
}

/// The set of address types enabled by config; an empty `network.address_types`
/// list means all address types are enabled.
pub(crate) fn configured_address_type_set(config: &VeilidConfig) -> AddressTypeSet {
    if config.network.address_types.is_empty() {
        return AddressTypeSet::all();
    }
    let mut set = AddressTypeSet::empty();
    for at in &config.network.address_types {
        set |= match at {
            VeilidConfigAddressType::Ipv4 => AddressType::IPV4,
            VeilidConfigAddressType::Ipv6 => AddressType::IPV6,
        };
    }
    set
}
