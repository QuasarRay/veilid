use super::*;

use crate::{
    network_manager::{connect as webtransport_connect, DialInfo, ProtocolType},
    routing_table::{DialInfoDetail, RoutingDomain},
};
use std::{collections::BTreeSet, net::SocketAddr};

// Dial info is published on the network's own tick, so poll for it instead of sleeping once
const DIAL_INFO_SETTLE_MS: u32 = 500;
const DIAL_INFO_SETTLE_TRIES: usize = 40;

fn webtransport_node_config(
    namespace: &str,
    listen: bool,
    wt_listen_address: &str,
    wt_path: &str,
) -> (UpdateCallback, VeilidConfig) {
    let (cb, mut config) = fixture_veilid_core_with_namespace(namespace);
    config.network.routing_table.bootstrap = vec![];
    config.network.routing_table.bootstrap_keys = vec![];
    config.network.protocol.udp.enabled = true;
    config.network.protocol.udp.listen_address = "".to_string();
    config.network.protocol.webtransport.connect = true;
    config.network.protocol.webtransport.listen = listen;
    config.network.protocol.webtransport.url = None;
    config.network.protocol.webtransport.listen_address = wt_listen_address.to_string();
    config.network.protocol.webtransport.path = wt_path.to_string();
    (cb, config)
}

fn published_dial_info(api: &VeilidAPI) -> Vec<DialInfoDetail> {
    let routing_table = api.core_context().expect("core context").routing_table();
    let mut dids = routing_table.dial_info_details(RoutingDomain::LocalNetwork);
    dids.extend(routing_table.dial_info_details(RoutingDomain::PublicInternet));
    dids
}

fn advertised_addrs(dids: &[DialInfoDetail], pt: ProtocolType) -> BTreeSet<SocketAddr> {
    dids.iter()
        .filter(|d| d.dial_info.protocol_type() == pt)
        .map(|d| d.dial_info.to_socket_addr())
        .collect()
}

fn wts_cert_hashes(dids: &[DialInfoDetail]) -> BTreeSet<[u8; 32]> {
    dids.iter()
        .filter_map(|d| match &d.dial_info {
            DialInfo::WebTransportStream(di) => Some(di.cert_hashes.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect()
}

async fn wait_for_udp_dial_info(api: &VeilidAPI) -> Vec<DialInfoDetail> {
    for _ in 0..DIAL_INFO_SETTLE_TRIES {
        let dids = published_dial_info(api);
        if !advertised_addrs(&dids, ProtocolType::UDP).is_empty() {
            return dids;
        }
        sleep(DIAL_INFO_SETTLE_MS).await;
    }
    panic!("node never advertised UDP dial info (no usable network interface?)");
}

async fn wait_for_dial_info_of(api: &VeilidAPI, pt: ProtocolType) -> Vec<DialInfoDetail> {
    for _ in 0..DIAL_INFO_SETTLE_TRIES {
        let dids = published_dial_info(api);
        if !advertised_addrs(&dids, pt).is_empty() {
            return dids;
        }
        sleep(DIAL_INFO_SETTLE_MS).await;
    }
    panic!("node never advertised {pt:?} dial info");
}

/// Discover a real, non-loopback local interface IP without sending any network traffic:
/// `connect` on a UDP socket only consults the local routing table to pick a source address,
/// so the address it binds names a routable interface. `None` when there is no such interface,
/// as on an offline or routeless host.
fn discover_non_loopback_interface_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(ip)
}

async fn test_webtransport_advertised_with_udp() {
    info!("test_webtransport_advertised_with_udp: starting");

    let (cb, config) = webtransport_node_config("wt_e2e_on", true, "", "wt");
    let api = api_startup(cb, config).await.expect("node startup");
    api.attach().await.expect("attach");

    let dids = wait_for_udp_dial_info(&api).await;
    let udp_addrs = advertised_addrs(&dids, ProtocolType::UDP);
    let wts_addrs = advertised_addrs(&dids, ProtocolType::WTS);
    let wtd_addrs = advertised_addrs(&dids, ProtocolType::WTD);

    for addr in &udp_addrs {
        assert!(
            wts_addrs.contains(addr),
            "expected WTS dial info on UDP address {addr}; WTS addrs: {wts_addrs:?}"
        );
        assert!(
            wtd_addrs.contains(addr),
            "expected WTD dial info on UDP address {addr}; WTD addrs: {wtd_addrs:?}"
        );
    }

    for d in &dids {
        if let DialInfo::WebTransportStream(di) = &d.dial_info {
            assert!(
                !di.cert_hashes.is_empty(),
                "self-signed WTS dial info must carry certificate hashes"
            );
        }
    }

    api.detach().await.ok();
    api.shutdown().await;
    info!("test_webtransport_advertised_with_udp: finished");
}

async fn test_webtransport_listen_disabled_advertises_no_wt() {
    info!("test_webtransport_listen_disabled_advertises_no_wt: starting");

    let (cb, config) = webtransport_node_config("wt_e2e_off", false, "", "wt");
    let api = api_startup(cb, config).await.expect("node startup");
    api.attach().await.expect("attach");

    let dids = wait_for_udp_dial_info(&api).await;
    assert!(
        advertised_addrs(&dids, ProtocolType::WTS).is_empty(),
        "WebTransport listening disabled: no WTS dial info should be advertised"
    );
    assert!(
        advertised_addrs(&dids, ProtocolType::WTD).is_empty(),
        "WebTransport listening disabled: no WTD dial info should be advertised"
    );

    api.detach().await.ok();
    api.shutdown().await;
    info!("test_webtransport_listen_disabled_advertises_no_wt: finished");
}

async fn test_webtransport_cert_persists_across_restart() {
    info!("test_webtransport_cert_persists_across_restart: starting");

    let (cb, mut config) = webtransport_node_config("wt_e2e_persist", true, "", "wt");
    config.table_store.delete = false;
    config.block_store.delete = false;
    config.protected_store.delete = false;

    let api1 = api_startup(cb.clone(), config.clone())
        .await
        .expect("node startup 1");
    api1.attach().await.expect("attach 1");
    let hashes1 = wts_cert_hashes(&wait_for_udp_dial_info(&api1).await);
    assert!(
        !hashes1.is_empty(),
        "first boot must advertise self-signed WTS cert hashes"
    );
    api1.detach().await.ok();
    api1.shutdown().await;

    let api2 = api_startup(cb, config).await.expect("node startup 2");
    api2.attach().await.expect("attach 2");
    let hashes2 = wts_cert_hashes(&wait_for_udp_dial_info(&api2).await);
    assert_eq!(
        hashes1, hashes2,
        "WebTransport self-signed cert hash must persist across a process restart"
    );
    api2.detach().await.ok();
    api2.shutdown().await;

    info!("test_webtransport_cert_persists_across_restart: finished");
}

async fn test_webtransport_cert_error_degrades_not_aborts() {
    info!("test_webtransport_cert_error_degrades_not_aborts: starting");

    let (cb, mut config) = webtransport_node_config("wt_e2e_cert_err", true, "", "wt");
    config.network.protocol.webtransport.url = Some("https://127.0.0.1:5150/".to_string());
    config.network.tls.certificate_path = "/nonexistent/veilid-wt-cert.pem".to_string();
    config.network.tls.private_key_path = "/nonexistent/veilid-wt-key.pem".to_string();

    let api = api_startup(cb, config)
        .await
        .expect("node startup must succeed despite a WebTransport cert error");
    api.attach().await.expect("attach");

    let dids = wait_for_udp_dial_info(&api).await;
    assert!(
        advertised_addrs(&dids, ProtocolType::WTS).is_empty(),
        "WT cert error must degrade gracefully: no WTS dial info should be advertised"
    );
    assert!(
        advertised_addrs(&dids, ProtocolType::WTD).is_empty(),
        "WT cert error must degrade gracefully: no WTD dial info should be advertised"
    );

    api.detach().await.ok();
    api.shutdown().await;
    info!("test_webtransport_cert_error_degrades_not_aborts: finished");
}

async fn test_webtransport_listen_address_coincide_shares_udp_socket() {
    info!("test_webtransport_listen_address_coincide_shares_udp_socket: starting");

    let (cb, mut config) = webtransport_node_config("wt_e2e_coincide", true, ":0", "wt");
    config.network.protocol.udp.listen_address = ":0".to_string();
    let api = api_startup(cb, config).await.expect("node startup");
    api.attach().await.expect("attach");

    let dids = wait_for_udp_dial_info(&api).await;
    let udp_addrs = advertised_addrs(&dids, ProtocolType::UDP);
    let wts_addrs = advertised_addrs(&dids, ProtocolType::WTS);
    let wtd_addrs = advertised_addrs(&dids, ProtocolType::WTD);

    assert!(
        !udp_addrs.is_empty(),
        "expected UDP dial info to be advertised"
    );
    assert_eq!(
        wts_addrs, udp_addrs,
        "a coincident wt listen_address must share the UDP socket: WTS addrs {wts_addrs:?} must equal UDP addrs {udp_addrs:?}"
    );
    assert_eq!(
        wtd_addrs, udp_addrs,
        "a coincident wt listen_address must share the UDP socket: WTD addrs {wtd_addrs:?} must equal UDP addrs {udp_addrs:?}"
    );

    api.detach().await.ok();
    api.shutdown().await;
    info!("test_webtransport_listen_address_coincide_shares_udp_socket: finished");
}

async fn test_webtransport_advertised_urls_carry_path() {
    info!("test_webtransport_advertised_urls_carry_path: starting");

    let (cb, config) = webtransport_node_config("wt_e2e_path", true, "", "wt");
    let api = api_startup(cb, config).await.expect("node startup");
    api.attach().await.expect("attach");

    let dids = wait_for_udp_dial_info(&api).await;
    let mut wt_count = 0usize;
    for d in &dids {
        let pt = d.dial_info.protocol_type();
        if pt != ProtocolType::WTS && pt != ProtocolType::WTD {
            continue;
        }
        let Some(request) = d.dial_info.request() else {
            continue;
        };
        wt_count += 1;
        let url = url::Url::parse(&request)
            .unwrap_or_else(|e| panic!("advertised webtransport url {request:?} must parse: {e}"));
        assert_eq!(
            url.path().trim_matches('/'),
            "wt",
            "advertised webtransport url {request:?} must carry the configured path"
        );
    }
    assert!(
        wt_count > 0,
        "expected at least one advertised WebTransport (WTS/WTD) dial info"
    );

    api.detach().await.ok();
    api.shutdown().await;
    info!("test_webtransport_advertised_urls_carry_path: finished");
}

async fn test_webtransport_dedicated_listen_address() {
    info!("test_webtransport_dedicated_listen_address: starting");

    let Some(ifip) = discover_non_loopback_interface_ip() else {
        info!("test_webtransport_dedicated_listen_address: skipping, no routable non-loopback interface found");
        return;
    };

    let (cb, mut config) =
        webtransport_node_config("wt_e2e_dedicated", true, &format!("{ifip}:0"), "wt");
    config.network.protocol.udp.listen_address = "".to_string();
    let api = api_startup(cb, config).await.expect("node startup");
    api.attach().await.expect("attach");

    let _ = wait_for_udp_dial_info(&api).await;
    let dids = wait_for_dial_info_of(&api, ProtocolType::WTS).await;

    let udp_addrs = advertised_addrs(&dids, ProtocolType::UDP);
    let wts_addrs = advertised_addrs(&dids, ProtocolType::WTS);
    let wtd_addrs = advertised_addrs(&dids, ProtocolType::WTD);

    assert!(
        !wts_addrs.is_empty(),
        "expected a dedicated WTS dial info to be advertised"
    );
    let udp_ports: BTreeSet<u16> = udp_addrs.iter().map(SocketAddr::port).collect();
    for wts_addr in &wts_addrs {
        assert!(
            !udp_ports.contains(&wts_addr.port()),
            "dedicated WTS port {} must not coincide with any UDP-advertised port {udp_ports:?}",
            wts_addr.port()
        );
        assert!(
            !udp_addrs.contains(wts_addr),
            "no UDP dial info should exist at dedicated WTS address {wts_addr}"
        );
    }
    assert_eq!(
        wts_addrs, wtd_addrs,
        "WTS and WTD must advertise the same address set in dedicated mode"
    );

    api.detach().await.ok();
    api.shutdown().await;
    info!("test_webtransport_dedicated_listen_address: finished");
}

async fn test_webtransport_wrong_path_rejected_404() {
    info!("test_webtransport_wrong_path_rejected_404: starting");

    let (cb, config) = webtransport_node_config("wt_e2e_404", true, "", "wt");
    let api = api_startup(cb, config).await.expect("node startup");
    api.attach().await.expect("attach");

    let dids = wait_for_udp_dial_info(&api).await;
    let wts_dial_infos: Vec<_> = dids
        .iter()
        .filter_map(|d| match &d.dial_info {
            DialInfo::WebTransportStream(di) => Some(di.clone()),
            _ => None,
        })
        .collect();
    // The node dials itself, which an address on a tunnel interface may not loop back, so
    // the routed interface's address comes first
    let routed_ip = discover_non_loopback_interface_ip();
    let wts_dial_info = wts_dial_infos
        .iter()
        .find(|di| Some(di.socket_address.ip_addr()) == routed_ip)
        .or(wts_dial_infos.first())
        .cloned()
        .expect("expected at least one advertised WTS dial info");

    let registry = api.core_context().expect("core context").registry();

    let mut wrong_url =
        url::Url::parse(&wts_dial_info.request).expect("advertised webtransport url must parse");
    wrong_url.set_path("/definitely-wrong");
    let wrong_dial_info = DialInfo::try_webtransport_stream(
        wts_dial_info.socket_address,
        wrong_url.to_string(),
        wts_dial_info.cert_hashes.clone(),
        None,
    )
    .expect("failed to build wrong-path dial info");

    const DIAL_ATTEMPTS: u32 = 5;

    let mut wrong_path_text = String::new();
    let mut saw_404 = false;
    for attempt in 0..DIAL_ATTEMPTS {
        if attempt > 0 {
            sleep(300).await;
        }
        let wrong_result =
            webtransport_connect(registry.clone(), None, wrong_dial_info.clone(), 5000, None).await;
        wrong_path_text = match wrong_result {
            Ok(NetworkResult::Value(_)) => {
                panic!("expected the wrong-path dial to be rejected, but it succeeded")
            }
            Ok(other) => format!("{other:?}"),
            Err(e) => format!("{e:?}"),
        };
        if wrong_path_text.contains("404") {
            saw_404 = true;
            break;
        }
    }
    assert!(
        saw_404,
        "expected the rejected dial to mention 404 within {DIAL_ATTEMPTS} attempts; last result: {wrong_path_text}"
    );

    let right_dial_info = DialInfo::WebTransportStream(wts_dial_info);
    let mut right_path_text = String::new();
    let mut saw_success = false;
    for attempt in 0..DIAL_ATTEMPTS {
        if attempt > 0 {
            sleep(300).await;
        }
        let right_result =
            webtransport_connect(registry.clone(), None, right_dial_info.clone(), 5000, None).await;
        right_path_text = match &right_result {
            Ok(v) => format!("{v:?}"),
            Err(e) => format!("{e:?}"),
        };
        if matches!(right_result, Ok(NetworkResult::Value(_))) {
            saw_success = true;
            break;
        }
    }
    assert!(
        saw_success,
        "expected the right-path dial to succeed within {DIAL_ATTEMPTS} attempts; last result: {right_path_text}"
    );

    api.detach().await.ok();
    api.shutdown().await;
    info!("test_webtransport_wrong_path_rejected_404: finished");
}

pub async fn test_all() {
    test_webtransport_advertised_with_udp().await;
    test_webtransport_listen_disabled_advertises_no_wt().await;
    test_webtransport_cert_persists_across_restart().await;
    test_webtransport_cert_error_degrades_not_aborts().await;
    test_webtransport_listen_address_coincide_shares_udp_socket().await;
    test_webtransport_advertised_urls_carry_path().await;
    test_webtransport_dedicated_listen_address().await;
    test_webtransport_wrong_path_rejected_404().await;
}
