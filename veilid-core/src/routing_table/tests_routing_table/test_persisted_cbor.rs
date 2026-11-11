//! Every routing-side type the table store persists survives its own encoding with real values.
//!
//! The tagged `DialInfo` is the shape that broke: a field whose serde impl depends on the format
//! does not round trip inside it under CBOR, which is how the persisted IP addresses were lost.

use super::*;
use crate::crypto::tests_crypto::*;
use crate::routing_table::network_estimator::NetworkEstimator;
use crate::tests::*;

fn check<T: Serialize + for<'a> Deserialize<'a> + PartialEq + fmt::Debug>(
    ts: &TableStore,
    value: &T,
    what: &str,
) {
    let copy: T = ts
        .try_deserialize(&serialize_table_value(value))
        .expect(what);
    assert_eq!(value, &copy, "{what}");
}

fn socket_addresses() -> [SocketAddress; 2] {
    [
        SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 160)), 5150),
        SocketAddress::new(
            Address::IPV6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            5150,
        ),
    ]
}

fn dial_infos() -> Vec<DialInfo> {
    let mut out = Vec::new();
    for socket_address in socket_addresses() {
        out.push(DialInfo::UDP(DialInfoUDP { socket_address }));
        out.push(DialInfo::TCP(DialInfoTCP { socket_address }));
        out.push(DialInfo::WS(DialInfoWS {
            socket_address,
            request: "example.com:5150/ws".to_owned(),
        }));
        #[cfg(feature = "enable-protocol-wss")]
        out.push(DialInfo::WSS(DialInfoWSS {
            socket_address,
            request: "example.com/ws".to_owned(),
        }));
    }
    out
}

pub async fn test_persisted_dial_info() {
    info!("--- test_persisted_dial_info ---");
    let registry = mock_registry::init("a").await;
    let ts = registry.table_store();

    for dial_info in dial_infos() {
        check(&ts, &dial_info, &format!("{dial_info}"));
        check(
            &ts,
            &DialInfoDetail {
                class: DialInfoClass::Direct,
                dial_info,
            },
            "dial info detail",
        );
    }

    mock_registry::terminate(registry).await;
}

pub async fn test_persisted_public_internet_state() {
    info!("--- test_persisted_public_internet_state ---");
    let registry = mock_registry::init("a").await;
    let ts = registry.table_store();

    let mut low_water_mark = LowWaterMark::new();
    low_water_mark.set(
        CRYPTO_KIND_VLD0,
        CapabilityCounts {
            any_capabilities: 12,
            connectivity_capabilities: 8,
            distance_metric_capabilities: 4,
        },
    );
    let node_id = registry
        .routing_table()
        .generate_node_id(&fake_public_key())
        .expect("node id");
    let payload = SignedBootstrapPayload::try_new_signed(
        &registry.crypto(),
        BootstrapPayload::new(
            Timestamp::new(1_700_000_000_000_000),
            Some(Timestamp::new(1_800_000_000_000_000)),
            None,
            vec![BootstrapNode::new(
                NodeIdGroup::from(vec![node_id]),
                dial_infos(),
            )],
        ),
        &[],
    )
    .expect("unsigned payload");
    let state = PublicInternetPersistedState {
        low_water_mark,
        bootstrap: Some(BootstrapCache::from_payload(
            &payload,
            Some(Timestamp::new(1_700_000_001_000_000)),
        )),
    };

    let copy: PublicInternetPersistedState = ts
        .try_deserialize(&serialize_table_value(&state))
        .expect("public internet state");
    assert_eq!(copy.low_water_mark, state.low_water_mark);
    assert_eq!(copy.bootstrap, state.bootstrap);

    mock_registry::terminate(registry).await;
}

pub async fn test_persisted_network_estimator() {
    info!("--- test_persisted_network_estimator ---");
    let registry = mock_registry::init("a").await;
    let ts = registry.table_store();

    let mut estimator = NetworkEstimator::new();
    let mut counts = vec![0usize; BUCKET_COUNT];
    counts[0] = 100;
    let observation = BTreeMap::from([(CRYPTO_KIND_VLD0, counts)]);
    estimator.record_observation(Timestamp::new(1_000_000), &observation, &BTreeMap::new());
    assert_ne!(estimator.estimate(CRYPTO_KIND_VLD0), 0);

    let copy: NetworkEstimator = ts
        .try_deserialize(&serialize_table_value(&estimator))
        .expect("network estimator");
    assert_eq!(
        copy.estimate(CRYPTO_KIND_VLD0),
        estimator.estimate(CRYPTO_KIND_VLD0)
    );
    assert_eq!(copy.estimate_combined(), estimator.estimate_combined());

    mock_registry::terminate(registry).await;
}
