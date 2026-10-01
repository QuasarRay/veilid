//! Which interface changes retire confirmed dial info: only changes to the routable set.

use super::*;

fn v4(ip: [u8; 4]) -> IfAddr {
    IfAddr::V4(Ifv4Addr {
        ip: Ipv4Addr::from(ip),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        broadcast: None,
    })
}

fn v6(ip: &str) -> IfAddr {
    IfAddr::V6(Ifv6Addr {
        ip: ip.parse().expect("test address"),
        netmask: "ffff:ffff:ffff:ffff::".parse().expect("test netmask"),
        broadcast: None,
    })
}

fn state(interface_addresses: Vec<IfAddr>) -> NetworkInterfaceAddressState {
    NetworkInterfaceAddressState {
        gateway_addresses: vec![],
        interface_addresses,
        own_addresses: vec![],
    }
}

/// The change seen on a phone between two thaws: one link-local address replaced
fn test_link_local_change_keeps_the_routable_set() {
    let before = state(vec![
        v4([192, 168, 0, 220]),
        v6("2600:1702:7d80:a0f:acad:9bff:fe3b:531"),
        v6("fe80::ac39:c3f2:9bea:53d0"),
    ]);
    let after = state(vec![
        v4([192, 168, 0, 220]),
        v6("2600:1702:7d80:a0f:acad:9bff:fe3b:531"),
        v6("fe80::ac39:c3f2:ce6b:8c65"),
    ]);
    assert_eq!(
        routable_interface_addresses(&before),
        routable_interface_addresses(&after)
    );
}

fn test_routable_change_is_seen() {
    let before = state(vec![v4([192, 168, 0, 220]), v6("2600:1702:7d80:a0f::1")]);
    let moved_v4 = state(vec![v4([192, 168, 0, 221]), v6("2600:1702:7d80:a0f::1")]);
    let moved_v6 = state(vec![v4([192, 168, 0, 220]), v6("2600:1702:7d80:a0f::2")]);
    let lost_v6 = state(vec![v4([192, 168, 0, 220])]);
    let before = routable_interface_addresses(&before);
    assert_ne!(before, routable_interface_addresses(&moved_v4));
    assert_ne!(before, routable_interface_addresses(&moved_v6));
    assert_ne!(before, routable_interface_addresses(&lost_v6));
}

fn test_loopback_and_link_local_are_not_routable() {
    let addresses = routable_interface_addresses(&state(vec![
        v4([127, 0, 0, 1]),
        v6("::1"),
        v6("fe80::1"),
        v4([169, 254, 1, 1]),
        v4([10, 0, 0, 5]),
    ]));
    assert_eq!(
        addresses,
        HashSet::from([Address::from_ip_addr(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 5
        )))])
    );
}

pub fn test_all() {
    test_link_local_change_keeps_the_routable_set();
    test_routable_change_is_seen();
    test_loopback_and_link_local_are_not_routable();
}
