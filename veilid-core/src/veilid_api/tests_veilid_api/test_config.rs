use super::*;
use crate::tests::*;

// The `internal()` accessor must ignore configured "footgun" tuning unless the
// `footgun-config` feature is enabled. This is the off-build runtime gate: a config
// carrying internal overrides still deserializes, but defaults are used.
pub fn test_internal_footgun_gate() {
    // Build a config whose internal tuning differs from the default.
    let mut tuned = VeilidConfigInternal::default();
    tuned.network.rpc.timeout_ms = tuned.network.rpc.timeout_ms.wrapping_add(1);
    assert_ne!(tuned, VeilidConfigInternal::default());

    let mut cfg = fake_veilid_config();
    cfg.internal = Some(tuned.clone());

    #[cfg(feature = "footgun-config")]
    {
        // With the feature, the configured tuning is honored.
        assert_eq!(*cfg.internal(), tuned);
    }
    #[cfg(not(feature = "footgun-config"))]
    {
        // Without the feature, footgun tuning is ignored and built-in defaults are used.
        assert_eq!(*cfg.internal(), VeilidConfigInternal::default());
    }
}

// A config saved before `network.bind_retry_ms` existed still deserializes, with the default
pub fn test_bind_retry_ms_defaults_when_absent() {
    let mut json = serde_json::to_value(fake_veilid_config()).expect("serialize");
    let network = json
        .get_mut("network")
        .and_then(|n| n.as_object_mut())
        .expect("network object");
    let removed = network
        .remove("bind_retry_ms")
        .or_else(|| network.remove("bindRetryMs"));
    assert!(removed.is_some(), "the field is serialized");

    let cfg: VeilidConfig = serde_json::from_value(json).expect("deserialize");
    assert_eq!(cfg.network.bind_retry_ms, 10_000);
}

fn object_at<'a>(
    json: &'a mut serde_json::Value,
    path: &[&str],
) -> &'a mut serde_json::Map<String, serde_json::Value> {
    path.iter()
        .fold(json, |v, key| v.get_mut(*key).expect("config path"))
        .as_object_mut()
        .expect("config object")
}

// A config carrying sections this build does not know, such as a newer core's or a feature's
// this build lacks, still deserializes and the sections are ignored
pub fn test_config_ignores_unknown_sections() {
    let mut json = serde_json::to_value(fake_veilid_config()).expect("serialize");
    let unknown = serde_json::json!({ "connect": true, "listen": false });
    object_at(&mut json, &[]).insert("future_section".to_string(), unknown.clone());
    object_at(&mut json, &["network"]).insert("future_section".to_string(), unknown.clone());
    object_at(&mut json, &["network", "protocol"]).insert("future_protocol".to_string(), unknown);

    let cfg: VeilidConfig = serde_json::from_value(json).expect("deserialize");
    assert_eq!(cfg, fake_veilid_config());
}

// The sections only a feature build has, as (parent object, keys in both casings)
const FEATURE_SECTIONS: [(&[&str], &[&str]); 4] = [
    (&["network", "protocol"], &["wss", "webtransport"]),
    (
        &["network", "privacy"],
        &["country_code_denylist", "countryCodeDenylist"],
    ),
    (&["network"], &["virtual_network", "virtualNetwork"]),
    (&["attachment"], &["app_lifecycle", "appLifecycle"]),
];

fn without_feature_sections(config: &VeilidConfig) -> serde_json::Value {
    let mut json = serde_json::to_value(config).expect("serialize");
    for (path, keys) in FEATURE_SECTIONS {
        let section = object_at(&mut json, path);
        for key in keys {
            section.remove(*key);
        }
    }
    json
}

// A config that leaves out the sections only a feature build has, as a binding does when they
// are unset, deserializes with their defaults
pub fn test_feature_sections_default_when_absent() {
    let fake = fake_veilid_config();
    let cfg: VeilidConfig =
        serde_json::from_value(without_feature_sections(&fake)).expect("deserialize");
    assert_eq!(
        without_feature_sections(&cfg),
        without_feature_sections(&fake)
    );
    #[cfg(feature = "enable-protocol-wss")]
    assert_eq!(cfg.network.protocol.wss, VeilidConfigWSS::default());
    #[cfg(feature = "enable-protocol-webtransport")]
    assert_eq!(
        cfg.network.protocol.webtransport,
        VeilidConfigWebTransport::default()
    );
    #[cfg(feature = "geolocation")]
    assert!(cfg.network.privacy.country_code_denylist.is_empty());
    #[cfg(feature = "virtual-network")]
    assert_eq!(
        cfg.network.virtual_network,
        VeilidConfigVirtualNetwork::default()
    );
    #[cfg(feature = "app-lifecycle")]
    assert_eq!(
        cfg.attachment.app_lifecycle,
        VeilidConfigAppLifecycle::default()
    );
}
