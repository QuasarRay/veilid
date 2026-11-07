use super::*;

pub fn test_protocol_config_without_webtransport_deserializes() {
    let mut value = serde_json::to_value(VeilidConfigProtocol::default()).unwrap();
    let obj = value.as_object_mut().unwrap();
    obj.remove("webtransport");
    obj.remove("webTransport");

    let parsed: VeilidConfigProtocol =
        serde_json::from_value(value).expect("config without webtransport must deserialize");
    assert_eq!(parsed.webtransport, VeilidConfigWebTransport::default());
}

pub fn test_webtransport_listen_address_and_path_defaults() {
    let d = VeilidConfigWebTransport::default();
    assert_eq!(d.listen_address, "");
    assert_eq!(d.path, "wt");
}

pub fn test_webtransport_listen_default_follows_platform() {
    let d = VeilidConfigWebTransport::default();
    assert!(d.connect, "default: outbound connect enabled");
    assert_eq!(
        d.listen,
        !cfg!(all(target_arch = "wasm32", target_os = "unknown")),
        "default: inbound listen is on wherever the platform can accept connections"
    );
}

pub fn test_webtransport_listen_address_and_path_roundtrip() {
    let cfg = VeilidConfigWebTransport {
        connect: true,
        listen: true,
        listen_address: "127.0.0.1:5150".to_string(),
        path: "custom".to_string(),
        url: None,
    };
    let value = serde_json::to_value(&cfg).unwrap();
    let parsed: VeilidConfigWebTransport = serde_json::from_value(value).unwrap();
    assert_eq!(parsed, cfg);
    assert_eq!(parsed.listen_address, "127.0.0.1:5150");
    assert_eq!(parsed.path, "custom");
}

pub fn test_webtransport_without_listen_address_or_path_deserializes_with_defaults() {
    let mut value = serde_json::to_value(VeilidConfigWebTransport::default()).unwrap();
    let obj = value.as_object_mut().unwrap();
    obj.remove("listen_address");
    obj.remove("listenAddress");
    obj.remove("path");

    let parsed: VeilidConfigWebTransport = serde_json::from_value(value)
        .expect("webtransport config without listen_address/path must deserialize");
    assert_eq!(parsed.listen_address, "");
    assert_eq!(parsed.path, "wt");
}

fn valid_test_config() -> VeilidConfig {
    let mut cfg = VeilidConfig {
        program_name: "test".to_string(),
        ..VeilidConfig::default()
    };
    cfg.network.tls.certificate_path = "/etc/ssl/certs/cert.pem".to_string();
    cfg.network.tls.private_key_path = "/etc/ssl/keys/key.pem".to_string();
    cfg
}

pub fn test_validate_rejects_webtransport_url_path_mismatch() {
    let mut cfg = valid_test_config();
    cfg.network.protocol.webtransport.listen = true;
    cfg.network.protocol.webtransport.path = "wt".to_string();
    cfg.network.protocol.webtransport.url = Some("https://example.com/other".to_string());
    assert!(cfg.validate().is_err());
}

pub fn test_validate_accepts_webtransport_url_path_match() {
    let mut cfg = valid_test_config();
    cfg.network.protocol.webtransport.listen = true;
    cfg.network.protocol.webtransport.path = "wt".to_string();
    cfg.network.protocol.webtransport.url = Some("https://example.com/wt/".to_string());
    assert!(cfg.validate().is_ok());
}

pub fn test_validate_accepts_webtransport_url_without_path() {
    let mut cfg = valid_test_config();
    cfg.network.protocol.webtransport.listen = true;
    cfg.network.protocol.webtransport.path = "wt".to_string();
    cfg.network.protocol.webtransport.url = Some("https://example.com/".to_string());
    assert!(cfg.validate().is_ok());
}

pub fn test_validate_rejects_webtransport_url_percent_escaped_path() {
    let mut cfg = valid_test_config();
    cfg.network.protocol.webtransport.listen = true;
    cfg.network.protocol.webtransport.path = "wt".to_string();
    cfg.network.protocol.webtransport.url = Some("https://example.com:5150/w%74".to_string());
    assert!(
        cfg.validate().is_err(),
        "a percent-escaped url path reaches the listener escaped and must not validate"
    );
}

pub fn test_validate_accepts_webtransport_url_path_needing_no_reencoding() {
    let mut cfg = valid_test_config();
    cfg.network.protocol.webtransport.listen = true;
    cfg.network.protocol.webtransport.path = "a;b".to_string();
    cfg.network.protocol.webtransport.url = Some("https://example.com:5150/a;b".to_string());
    assert!(cfg.validate().is_ok());
}

pub fn test_validate_accepts_staging_bootstrap_webtransport_config() {
    let mut cfg = valid_test_config();
    cfg.network.protocol.webtransport.listen = true;
    cfg.network.protocol.webtransport.path = String::new();
    cfg.network.protocol.webtransport.url =
        Some("https://bootstrap-v1.staging.veilid.net:5150/".to_string());
    assert!(cfg.validate().is_ok());
}

fn config_with_webtransport_path(path: &str) -> VeilidConfig {
    let mut cfg = valid_test_config();
    cfg.network.protocol.webtransport.listen = true;
    cfg.network.protocol.webtransport.path = path.to_string();
    cfg
}

pub fn test_validate_accepts_normalization_stable_webtransport_paths() {
    let at_cap = "a".repeat(MAX_WEBTRANSPORT_PATH_LENGTH - 1);
    let mut paths = vec![
        "wt", "wt/", "/wt/", "", "/", "///", "a/b", "wt%2Fx", "wt+x", "WT", "wt|x", "wt^x", "wt[x]",
    ];
    paths.push(&at_cap);
    for path in paths {
        assert!(
            config_with_webtransport_path(path).validate().is_ok(),
            "webtransport path {path:?} survives URL normalization and must validate"
        );
    }
}

pub fn test_validate_rejects_normalization_unstable_webtransport_paths() {
    let over_cap = "a".repeat(MAX_WEBTRANSPORT_PATH_LENGTH);
    let mut paths = vec![
        "a/../b", "a/./b", ".", "..", "my path", "wt ", "wt?x=1", "wt#frag", "wté", "wt\"x",
        "wt<x>", "wt{x}", "wt`x", "wt\\x",
    ];
    paths.push(&over_cap);
    for path in paths {
        assert!(
            config_with_webtransport_path(path).validate().is_err(),
            "webtransport path {path:?} would 404 its own advertisement and must not validate"
        );
    }
}

pub fn test_validate_accepts_webtransport_listen_without_udp() {
    let mut cfg = valid_test_config();
    cfg.network.protocol.webtransport.listen = true;
    cfg.network.protocol.udp.enabled = false;
    assert!(
        cfg.validate().is_ok(),
        "a webtransport-only node listens on a dedicated socket"
    );
}

pub fn test_validate_accepts_webtransport_off_without_udp() {
    let mut cfg = valid_test_config();
    cfg.network.protocol.webtransport.listen = false;
    cfg.network.protocol.udp.enabled = false;
    assert!(cfg.validate().is_ok());
}

pub fn test_all() {
    test_protocol_config_without_webtransport_deserializes();
    test_webtransport_listen_address_and_path_defaults();
    test_webtransport_listen_default_follows_platform();
    test_webtransport_listen_address_and_path_roundtrip();
    test_webtransport_without_listen_address_or_path_deserializes_with_defaults();
    test_validate_rejects_webtransport_url_path_mismatch();
    test_validate_accepts_webtransport_url_path_match();
    test_validate_accepts_webtransport_url_without_path();
    test_validate_rejects_webtransport_url_percent_escaped_path();
    test_validate_accepts_webtransport_url_path_needing_no_reencoding();
    test_validate_accepts_staging_bootstrap_webtransport_config();
    test_validate_accepts_normalization_stable_webtransport_paths();
    test_validate_rejects_normalization_unstable_webtransport_paths();
    test_validate_accepts_webtransport_listen_without_udp();
    test_validate_accepts_webtransport_off_without_udp();
}
