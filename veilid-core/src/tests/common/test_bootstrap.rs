use super::*;
use crate::network_manager::*;
use crate::routing_table::*;

const BOOTSTRAP_PAYLOAD_WAIT_MS: u32 = 90_000;
const DIRECT_BOOTSTRAP_ATTEMPTS: u32 = 30;
const POLL_MS: u32 = 1000;

fn registry(api: &VeilidAPI) -> VeilidComponentRegistry {
    api.core_context().expect("api not started").registry()
}

/// The payload a node serves, once it has one
async fn wait_for_bootstrap_payload(api: &VeilidAPI) -> Option<SignedBootstrapPayload> {
    let routing_table = registry(api).routing_table();
    let mut waited_ms = 0;
    loop {
        let cache = routing_table.get_served_bootstrap_cache(RoutingDomain::PublicInternet);
        let payload = cache.served_payload(Timestamp::now());
        if payload.is_some() || waited_ms >= BOOTSTRAP_PAYLOAD_WAIT_MS {
            return payload;
        }
        sleep(POLL_MS).await;
        waited_ms += POLL_MS;
    }
}

async fn wait_for_network_started(api: &VeilidAPI) {
    while !api.get_state().await.unwrap().network.started {
        sleep(POLL_MS).await;
    }
}

fn local_udp_bootstrap_url(api: &VeilidAPI) -> String {
    let did = registry(api)
        .routing_table()
        .dial_info_details(RoutingDomain::LocalNetwork)
        .into_iter()
        .find(|d| {
            d.dial_info.protocol_type() == ProtocolType::UDP
                && d.dial_info.address_type() == AddressType::IPV4
        })
        .expect("no local ipv4 udp dial info");
    format!("udp://{}", did.dial_info.to_socket_addr())
}

/// Node A bootstraps from the configured network and keeps the payload it was handed.
/// Node B lists only A, so everything it learns arrives over B02T. Needs bootstraps that
/// answer B02T, so this runs against a 0.6.0 fleet, not in the unit-test script
async fn test_direct_bootstrap() -> SignedBootstrapPayload {
    info!("test_direct_bootstrap: starting node A");
    let (update_callback, mut config) = fixture_veilid_core();
    // Serving bootstrap is opt-in, and A is not among its own bootstraps
    config.network.routing_table.serve_direct_bootstrap = true;
    config.network.routing_table.bootstrap_protocols = vec![
        VeilidConfigBootstrapProtocol::Wss,
        VeilidConfigBootstrapProtocol::Wts,
        VeilidConfigBootstrapProtocol::Udp,
        VeilidConfigBootstrapProtocol::Tcp,
    ];
    let api_a = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    api_a.attach().await.unwrap();
    let _ = api_a
        .wait_for_attachment_condition(None, None)
        .await
        .unwrap();

    let payload_a = wait_for_bootstrap_payload(&api_a)
        .await
        .expect("bootstrap handed node A no payload");
    let reply = registry(&api_a)
        .network_manager()
        .boot_v2_response()
        .expect("node A should build a B02T reply");
    assert_eq!(&reply[..4], B02T_MAGIC);

    // A never bootstraps from itself, so a request to its own dial info is not sent
    let own_dial_info = BootstrapDialInfoConverter::default()
        .try_vec_from_url(&local_udp_bootstrap_url(&api_a))
        .await
        .expect("bad bootstrap url")
        .remove(0);
    let own_peers = registry(&api_a)
        .network_manager()
        .direct_bootstrap(own_dial_info)
        .await
        .expect("direct bootstrap failed");
    assert!(own_peers.peers.is_empty() && own_peers.payload.is_none());

    info!("test_direct_bootstrap: starting node B");
    let url = local_udp_bootstrap_url(&api_a);
    let (update_callback, mut config) = fixture_veilid_core();
    config.network.routing_table.bootstrap = vec![url.clone()];
    let api_b = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    api_b.attach().await.unwrap();
    wait_for_network_started(&api_b).await;

    // One B02T round trip returns the payload A holds, as the bytes A holds it
    let dial_info = BootstrapDialInfoConverter::default()
        .try_vec_from_url(&url)
        .await
        .expect("bad bootstrap url")
        .remove(0);
    let network_manager_b = registry(&api_b).network_manager();
    let mut payload_b = None;
    for _ in 0..DIRECT_BOOTSTRAP_ATTEMPTS {
        let peers = network_manager_b
            .direct_bootstrap(dial_info.clone())
            .await
            .expect("direct bootstrap failed");
        payload_b = peers.payload;
        if payload_b.is_some() {
            break;
        }
        sleep(POLL_MS).await;
    }
    assert_eq!(payload_b.as_ref(), Some(&payload_a));

    // B's own bootstrap task records what A handed it
    let cache_b = wait_for_bootstrap_payload(&api_b)
        .await
        .expect("direct bootstrap stored no payload");
    assert_eq!(cache_b, payload_a);

    // Having recorded a bootstrap, neither node's saved table is condemned on the next start
    registry(&api_a)
        .routing_table()
        .flush(SaveReason::Bootstrap)
        .await;
    assert!(!persisted_state_requires_reset(&api_a).await);

    info!("test_direct_bootstrap: shutting down");
    api_b.shutdown().await;
    api_a.shutdown().await;

    payload_a
}

/// Node C is told the payload outright, so it joins by asking the payload's own nodes, with no
/// bootstrap host configured at all; it serves the payload before it has bootstrapped
async fn test_config_payload_bootstrap(payload_a: &SignedBootstrapPayload) {
    info!("test_config_payload_bootstrap: starting node C");
    let (update_callback, mut config) = fixture_veilid_core();
    config.network.routing_table.bootstrap = vec![];
    config.network.routing_table.bootstrap_records = vec![payload_a.to_line()];
    let api_c = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    api_c.attach().await.unwrap();

    wait_for_network_started(&api_c).await;
    let served = registry(&api_c)
        .routing_table()
        .get_served_bootstrap_cache(RoutingDomain::PublicInternet);
    assert_eq!(
        served.served_payload(Timestamp::now()).as_ref(),
        Some(payload_a)
    );
    assert_eq!(served.received_at(), None);

    // And good enough to join with
    let _ = api_c
        .wait_for_attachment_condition(None, None)
        .await
        .unwrap();

    info!("test_config_payload_bootstrap: shutting down");
    api_c.shutdown().await;
}

/// Node D has no bootstrap keys, so it takes the payload and peers unsigned
async fn test_keyless_bootstrap() {
    info!("test_keyless_bootstrap: starting node D");
    let (update_callback, mut config) = fixture_veilid_core();
    config.network.routing_table.bootstrap_keys = vec![];
    let api_d = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    api_d.attach().await.unwrap();
    let _ = api_d
        .wait_for_attachment_condition(None, None)
        .await
        .unwrap();
    assert!(wait_for_bootstrap_payload(&api_d).await.is_some());
    info!("test_keyless_bootstrap: shutting down");
    api_d.shutdown().await;
}

async fn persisted_state_requires_reset(api: &VeilidAPI) -> bool {
    let registry = registry(api);
    let table_store = registry.table_store();
    let db = table_store
        .open(
            "routing_table",
            crate::routing_table::ROUTING_TABLE_COLUMN_COUNT,
        )
        .await
        .expect("should open routing table db");
    let routing_table = registry.routing_table();
    let rdc = routing_table.get_routing_domain_controller(RoutingDomain::PublicInternet);
    rdc.persisted_state_requires_reset(&db).await
}

pub async fn test_all() {
    let payload_a = test_direct_bootstrap().await;
    test_config_payload_bootstrap(&payload_a).await;
    test_keyless_bootstrap().await;
}
