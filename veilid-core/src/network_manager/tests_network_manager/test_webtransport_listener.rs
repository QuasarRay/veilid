use super::*;
use crate::network_manager::network::native::start_protocols::NetworkBindSet;
use crate::network_manager::network::native::tls_certificates::sibling_ip_path;
use crate::network_manager::network::native::webtransport_listener::{
    same_bind_target, webtransport_path_matches, webtransport_request_url,
    webtransport_socket_request_url, WebTransportBindPlan,
};
use crate::network_manager::network::native::NativeNetwork;
use crate::tests::*;
use crate::MAX_WEBTRANSPORT_PATH_LENGTH;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

pub fn test_sibling_ip_path() {
    // The sibling joins the base's directory with the platform's separator
    let sibling = |dir: &str, name: &str| {
        std::path::Path::new(dir)
            .join(name)
            .to_str()
            .map(str::to_owned)
    };
    assert_eq!(
        sibling_ip_path("/etc/veilid-server/ssl/certs/server.crt", "ipv4"),
        sibling("/etc/veilid-server/ssl/certs", "ipv4.crt")
    );
    assert_eq!(
        sibling_ip_path("/etc/veilid-server/ssl/keys/server.key", "ipv6"),
        sibling("/etc/veilid-server/ssl/keys", "ipv6.key")
    );
    assert_eq!(
        sibling_ip_path("/srv/tls/fullchain.pem", "ipv4"),
        sibling("/srv/tls", "ipv4.pem")
    );
    assert_eq!(
        sibling_ip_path("/srv/tls/server", "ipv6"),
        sibling("/srv/tls", "ipv6")
    );
    assert_eq!(sibling_ip_path("", "ipv4"), None);
}

fn bind_set(port: u16, addrs: &[IpAddr], search: bool) -> NetworkBindSet {
    NetworkBindSet {
        port,
        addrs: addrs.to_vec(),
        search,
    }
}

pub fn test_same_bind_target_equal_port_and_addrs() {
    let v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    let a = bind_set(5150, &[v4, v6], true);
    let b = bind_set(5150, &[v4, v6], true);
    assert!(same_bind_target(&a, &b));
}

pub fn test_same_bind_target_ignores_search_flag() {
    let v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let a = bind_set(5150, &[v4], true);
    let b = bind_set(5150, &[v4], false);
    assert!(same_bind_target(&a, &b));
}

pub fn test_same_bind_target_order_insensitive() {
    let v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    let a = bind_set(5150, &[v4, v6], true);
    let b = bind_set(5150, &[v6, v4], true);
    assert!(same_bind_target(&a, &b));
}

pub fn test_same_bind_target_port_differs() {
    let v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let a = bind_set(5150, &[v4], true);
    let b = bind_set(5151, &[v4], true);
    assert!(!same_bind_target(&a, &b));
}

pub fn test_same_bind_target_addr_sets_differ() {
    let a_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a = bind_set(5150, &[a_ip], true);
    let b = bind_set(5150, &[b_ip], true);
    assert!(!same_bind_target(&a, &b));
}

pub fn test_same_bind_target_partial_overlap() {
    let common = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let a_only = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let b_only = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let a = bind_set(5150, &[common, a_only], true);
    let b = bind_set(5150, &[common, b_only], true);
    assert!(!same_bind_target(&a, &b));
}

pub fn test_same_bind_target_subset() {
    let common = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let extra = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a = bind_set(5150, &[common], true);
    let b = bind_set(5150, &[common, extra], true);
    assert!(!same_bind_target(&a, &b));
}

pub fn test_webtransport_path_matches_table() {
    let cases = [
        ("/wt", "wt", true),
        ("/wt/", "wt", true),
        ("wt", "wt", true),
        ("/", "", true),
        ("", "", true),
        ("/wt/x", "wt", false),
        ("/xwt", "wt", false),
        ("/", "wt", false),
        ("/wt", "/wt", true),
        ("/wt", "wt/", true),
        ("/wt", "/wt/", true),
        ("/", "///", true),
        ("/wt", "/xt/", false),
    ];
    for (request_path, expected_trimmed, want) in cases {
        assert_eq!(
            webtransport_path_matches(request_path, expected_trimmed),
            want,
            "webtransport_path_matches({request_path:?}, {expected_trimmed:?}) should be {want}"
        );
    }
}

pub fn test_webtransport_path_matches_rejects_oversize_path() {
    let expected = "wt";
    let padding = MAX_WEBTRANSPORT_PATH_LENGTH - expected.len() - 1;
    let at_cap = format!("/{}{}", expected, "/".repeat(padding));
    assert_eq!(at_cap.len(), MAX_WEBTRANSPORT_PATH_LENGTH);
    assert!(
        webtransport_path_matches(&at_cap, expected),
        "a path at the cap must still match"
    );

    let over_cap = format!("{}/", at_cap);
    assert_eq!(over_cap.len(), MAX_WEBTRANSPORT_PATH_LENGTH + 1);
    assert!(
        !webtransport_path_matches(&over_cap, expected),
        "a path over the cap must be rejected on length"
    );

    let junk = format!("/{}", "a".repeat(MAX_WEBTRANSPORT_PATH_LENGTH));
    assert!(
        !webtransport_path_matches(&junk, expected),
        "an oversize non-matching path must be rejected"
    );
}

pub fn test_webtransport_request_url_injects_port_and_path() {
    assert_eq!(
        webtransport_request_url("https://host/", Some(5150), "wt").unwrap(),
        "https://host:5150/wt"
    );
    assert_eq!(
        webtransport_request_url("https://host:5150/wt", None, "wt").unwrap(),
        "https://host:5150/wt"
    );
    assert_eq!(
        webtransport_request_url("https://host:5150/", None, "").unwrap(),
        "https://host:5150/"
    );
}

pub fn test_webtransport_request_url_keeps_url_crate_encoding() {
    for path in ["a;b", "a[b]", "a|b", "a^b"] {
        assert_eq!(
            webtransport_request_url("https://host:5150/", None, path).unwrap(),
            format!("https://host:5150/{path}"),
            "SplitUrl would percent-encode this path where the url crate does not"
        );
    }
}

pub fn test_webtransport_request_url_dials_its_own_accept_route() {
    for path in ["", "wt", "a;b", "a[b]", "a/b"] {
        let request_url = webtransport_request_url("https://host:5150/", None, path).unwrap();
        let dialed = url::Url::parse(&request_url).expect("a peer parses the advertised url");
        assert!(
            webtransport_path_matches(dialed.path(), path),
            "advertised {request_url:?} must match the listener's expected path {path:?}"
        );
    }
}

pub fn test_webtransport_socket_request_url_brackets_and_paths() {
    let v4: SocketAddr = "203.0.113.5:5150".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::1]:5150".parse().unwrap();
    assert_eq!(
        webtransport_socket_request_url(v4, "").unwrap(),
        "https://203.0.113.5:5150/"
    );
    assert_eq!(
        webtransport_socket_request_url(v4, "wt").unwrap(),
        "https://203.0.113.5:5150/wt"
    );
    assert_eq!(
        webtransport_socket_request_url(v6, "wt").unwrap(),
        "https://[2001:db8::1]:5150/wt"
    );
}

fn conflicts(bound: &[&str], addr: &str) -> bool {
    let bound_raw_udp_addrs = bound
        .iter()
        .map(|a| a.parse::<SocketAddr>().expect("bound addr"))
        .collect::<BTreeSet<SocketAddr>>();
    NativeNetwork::webtransport_udp_delivery_conflict(
        &bound_raw_udp_addrs,
        addr.parse::<SocketAddr>().expect("candidate addr"),
    )
}

pub fn test_webtransport_udp_delivery_conflict_same_port() {
    assert!(conflicts(&["203.0.113.5:5150"], "203.0.113.5:5150"));
}

pub fn test_webtransport_udp_delivery_conflict_wildcard_ip() {
    assert!(conflicts(&["0.0.0.0:5150"], "203.0.113.5:5150"));
    assert!(conflicts(&["203.0.113.5:5150"], "0.0.0.0:5150"));
}

pub fn test_webtransport_udp_delivery_conflict_family_mismatch() {
    assert!(!conflicts(&["0.0.0.0:5150"], "[2001:db8::1]:5150"));
    assert!(!conflicts(&["[::]:5150"], "203.0.113.5:5150"));
}

pub fn test_webtransport_udp_delivery_conflict_different_port() {
    assert!(!conflicts(&["203.0.113.5:5150"], "203.0.113.5:5151"));
    assert!(!conflicts(&["0.0.0.0:5150"], "203.0.113.5:5151"));
}

/// A network listening for WebTransport in self-signed mode, so a bind plan reaches the
/// bind target comparison instead of stopping at a missing certificate.
async fn bind_plan_network(
    namespace: &str,
    wt_listen_address: &str,
) -> (VeilidComponentRegistry, NativeNetwork) {
    let registry = mock_registry::init_with_config(namespace, |config| {
        config.network.protocol.webtransport.listen = true;
        config.network.protocol.webtransport.url = None;
        config.network.protocol.webtransport.listen_address = wt_listen_address.to_string();
    })
    .await;
    let net = NativeNetwork::new(registry.clone());
    net.startup_certificate_manager()
        .await
        .expect("should start the webtransport certificate manager");
    (registry, net)
}

fn plan_against_udp(net: &NativeNetwork, udp_listen_address: &str) -> WebTransportBindPlan {
    let udp_bind_set =
        NetworkBindSet::from_str(udp_listen_address).expect("should parse the udp listen address");
    net.webtransport_bind_plan(Some(&udp_bind_set))
        .expect("should plan a webtransport bind")
}

pub async fn test_webtransport_bind_plan_explicit_listen_address() {
    let (registry, net) = bind_plan_network("wt_bind_plan_explicit", ":5150").await;
    assert!(
        matches!(
            plan_against_udp(&net, ":5150"),
            WebTransportBindPlan::Shared(_)
        ),
        "a webtransport listen_address equal to udp's must share the UDP socket"
    );
    assert!(
        matches!(
            plan_against_udp(&net, ":5151"),
            WebTransportBindPlan::Dedicated(..)
        ),
        "a webtransport listen_address on another port must bind a dedicated socket"
    );
    mock_registry::terminate(registry).await;
}

pub async fn test_webtransport_bind_plan_default_listen_address() {
    let (registry, net) = bind_plan_network("wt_bind_plan_default", "").await;
    assert!(
        matches!(plan_against_udp(&net, ""), WebTransportBindPlan::Shared(_)),
        "the default listen_address on both protocols must share the UDP socket"
    );
    mock_registry::terminate(registry).await;
}
