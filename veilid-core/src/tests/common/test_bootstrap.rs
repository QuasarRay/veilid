use super::*;
use crate::network_manager::*;
use crate::routing_table::*;

const BOOTSTRAP_RECORDS_WAIT_MS: u32 = 90_000;
const DIRECT_BOOTSTRAP_ATTEMPTS: u32 = 30;
const POLL_MS: u32 = 1000;

fn registry(api: &VeilidAPI) -> VeilidComponentRegistry {
    api.core_context().expect("api not started").registry()
}

fn signed_strings(records: &[BootstrapRecord]) -> BTreeSet<String> {
    records
        .iter()
        .flat_map(|r| r.signed_strings().iter().cloned())
        .collect()
}

async fn wait_for_bootstrap_records(api: &VeilidAPI) -> Vec<BootstrapRecord> {
    let routing_table = registry(api).routing_table();
    let mut waited_ms = 0;
    loop {
        let records = routing_table.get_bootstrap_records(RoutingDomain::PublicInternet);
        if !records.is_empty() || waited_ms >= BOOTSTRAP_RECORDS_WAIT_MS {
            return records;
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

/// Node A bootstraps from DNS and keeps its verified v1 records.
/// Node B lists only A as a bootstrap, so everything it learns arrives over B01T.
async fn test_txt_then_direct() {
    info!("test_txt_then_direct: starting node A");
    let (update_callback, config) = fixture_veilid_core();
    let api_a = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    api_a.attach().await.unwrap();
    fixture_wait_for_public_internet_ready(&api_a).await;

    let records_a = wait_for_bootstrap_records(&api_a).await;
    assert!(!records_a.is_empty(), "TXT bootstrap stored no records");
    let strings_a = signed_strings(&records_a);
    let response = registry(&api_a)
        .network_manager()
        .boot_v1_response()
        .expect("node A should serve B01T");
    assert_eq!(
        response.records.iter().cloned().collect::<BTreeSet<_>>(),
        strings_a
    );

    info!("test_txt_then_direct: starting node B");
    let url = local_udp_bootstrap_url(&api_a);
    let (update_callback, mut config) = fixture_veilid_core();
    config.network.routing_table.bootstrap = vec![url.clone()];
    let api_b = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    api_b.attach().await.unwrap();
    wait_for_network_started(&api_b).await;

    // One B01T round trip returns exactly what A stored
    let dial_info = BootstrapDialInfoConverter::default()
        .try_vec_from_url(&url)
        .await
        .expect("bad bootstrap url")
        .remove(0);
    let network_manager_b = registry(&api_b).network_manager();
    let mut strings_b = BTreeSet::new();
    for _ in 0..DIRECT_BOOTSTRAP_ATTEMPTS {
        let peers = network_manager_b
            .direct_bootstrap(dial_info.clone())
            .await
            .expect("direct bootstrap failed");
        strings_b = signed_strings(&peers.records);
        if !strings_b.is_empty() {
            break;
        }
        sleep(POLL_MS).await;
    }
    assert_eq!(strings_b, strings_a);

    // B's own bootstrap task validates peers through A and stores what it validated
    let records_b = wait_for_bootstrap_records(&api_b).await;
    assert!(!records_b.is_empty(), "direct bootstrap stored no records");
    assert!(signed_strings(&records_b).is_subset(&strings_a));

    info!("test_txt_then_direct: shutting down");
    api_b.shutdown().await;
    api_a.shutdown().await;
}

pub async fn test_all() {
    test_txt_then_direct().await;
}
