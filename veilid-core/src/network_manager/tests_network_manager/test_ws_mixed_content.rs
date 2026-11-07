use super::*;
use crate::network_manager::network::wasm::ws::{ws_blocked_as_mixed_content, ws_target_is_local};
use std::net::{Ipv4Addr, Ipv6Addr};

fn v4(octets: [u8; 4]) -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::from(octets)), 5150)
}

fn ip_host(socket_address: SocketAddress) -> SplitUrlHost {
    SplitUrlHost::IpAddr(socket_address.ip_addr())
}

fn hostname(name: &str) -> SplitUrlHost {
    SplitUrlHost::Hostname(name.to_string())
}

// Only a loopback peer, or localhost named by a dial info with no address, is exempt from mixed content
pub fn test_ws_target_is_local() {
    let unspecified = v4([0, 0, 0, 0]);
    assert!(ws_target_is_local(&hostname("localhost"), unspecified));
    assert!(ws_target_is_local(&hostname("LocalHost"), unspecified));
    assert!(!ws_target_is_local(
        &hostname("bootstrap-v1.veilid.net"),
        unspecified
    ));

    let loopback = v4([127, 0, 0, 1]);
    assert!(ws_target_is_local(&ip_host(loopback), loopback));
    let loopback6 = SocketAddress::new(Address::IPV6(Ipv6Addr::LOCALHOST), 5150);
    assert!(ws_target_is_local(&ip_host(loopback6), loopback6));

    let public = v4([192, 0, 2, 1]);
    assert!(!ws_target_is_local(&ip_host(public), public));
    // The address decides once there is one
    assert!(!ws_target_is_local(&hostname("localhost"), public));
}

// Mixed content is an https page's rule: from the runner's http://127.0.0.1 page, a secure
// context, plain ws:// reaches any peer, as main's WS-only bootstraps need
pub fn test_ws_allowed_from_a_secure_http_page() {
    assert!(
        is_secure_context() && !is_browser_https(),
        "the wasm test runner serves its page over http from loopback, a secure context"
    );
    assert!(!ws_blocked_as_mixed_content(
        &hostname("bootstrap-v1.veilid.net"),
        v4([0, 0, 0, 0])
    ));
    let public = v4([192, 0, 2, 1]);
    assert!(!ws_blocked_as_mixed_content(&ip_host(public), public));
}
