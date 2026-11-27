//! What a node holds to answer bootstrap requests is decided by veilid-server's own config
//! mapping, so the configured payload is tested here and not only in veilid-core, beside the
//! config round trips and the operator flags that feed it.

#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
use crate::server::choose_legacy_hostname;
use crate::settings::*;
use clap::Parser as _;
use std::ffi::OsString;
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A global address stands in for public address detection: with it the node has PublicInternet
/// dial info and so a node line. Nothing is sent to it: a payload node's UDP and TCP dial infos
/// are outside the default bootstrap protocols
const STATIC_PUBLIC_ADDRESS: &str = "18.218.0.160";

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

fn test_dir(label: &str) -> PathBuf {
    let seq = TEST_SEQ.fetch_add(1, Ordering::AcqRel);
    let dir = std::env::temp_dir().join(format!(
        "veilid-server-test-{}-{}-{}",
        std::process::id(),
        label,
        seq
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("should make test dir");
    dir
}

/// A config file shaped like a real one, so what is under test is the production mapping
fn write_config(dir: &Path, network: &str) -> PathBuf {
    let conf = format!(
        r#"
daemon:
    enabled: false
client_api:
    ipc_enabled: false
    network_enabled: false
auto_attach: false
logging:
    system:
        enabled: false
    terminal:
        enabled: false
    file:
        enabled: false
    api:
        enabled: false
core:
    protected_store:
        allow_insecure_fallback: true
        always_use_insecure_storage: true
        directory: '{dir}/protected_store'
        delete: true
    table_store:
        directory: '{dir}/table_store'
        delete: true
    block_store:
        directory: '{dir}/block_store'
        delete: true
    network:
        upnp: false
        detect_address_changes: false
{network}
"#,
        dir = dir.display(),
    );
    let path = dir.join("veilid-server.conf");
    std::fs::write(&path, conf).expect("should write config");
    path
}

fn settings_for(path: &Path) -> Settings {
    Settings::try_new(Some(&OsString::from(path))).expect("should load settings")
}

fn network_block(port: u16, routing_table: &str) -> String {
    // Only udp and tcp have a static address, so nothing else listens
    #[cfg(feature = "enable-protocol-wss")]
    let wss = "\n            wss:\n                listen: false";
    #[cfg(not(feature = "enable-protocol-wss"))]
    let wss = "";
    #[cfg(feature = "enable-protocol-webtransport")]
    let webtransport = "\n            webtransport:\n                listen: false";
    #[cfg(not(feature = "enable-protocol-webtransport"))]
    let webtransport = "";
    format!(
        r#"        routing_table:
{routing_table}
        protocol:
            udp:
                enabled: true
                listen_address: ':{port}'
                public_address: '{STATIC_PUBLIC_ADDRESS}:{port}'
            tcp:
                connect: true
                listen: true
                listen_address: ':{port}'
                public_address: '{STATIC_PUBLIC_ADDRESS}:{port}'
            ws:
                connect: false
                listen: false{wss}{webtransport}"#
    )
}

/// A config written for an earlier build has no bootstrap_records or bootstrap_protocols key.
/// It has to keep mapping exactly as it does today
pub fn test_config_without_bootstrap_records() {
    let dir = test_dir("compat");
    let path = write_config(
        &dir,
        &network_block(
            5150,
            "            bootstrap: ['bootstrap-v1.veilid.net']\n            bootstrap_keys: ['VLD0:Vj0lKDdUQXmQ5Ol1SZdlvXkBHUccBcQvGLN9vbLSI7k']",
        ),
    );
    let settings = settings_for(&path);
    assert!(
        settings.unknown_keys.is_empty(),
        "unrecognized keys: {:?}",
        settings.unknown_keys
    );

    let core_config = settings.get_core_config(0, 0).expect("should map");
    let rt = &core_config.network.routing_table;
    assert_eq!(rt.bootstrap, vec!["bootstrap-v1.veilid.net".to_owned()]);
    assert_eq!(rt.bootstrap_keys.len(), 1);
    assert!(rt.bootstrap_records.is_empty());
    assert_eq!(
        rt.bootstrap_protocols,
        vec![
            veilid_core::VeilidConfigBootstrapProtocol::Wss,
            veilid_core::VeilidConfigBootstrapProtocol::Wts
        ]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Record lines and bootstrap protocols in the config file reach veilid-core verbatim
pub fn test_config_with_bootstrap_records() {
    let dir = test_dir("roundtrip");
    let record = "2|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let path = write_config(
        &dir,
        &network_block(
            5150,
            &format!(
                "            bootstrap: []\n            bootstrap_protocols: ['UDP', 'tcp']\n            bootstrap_records:\n                - '{}'",
                record
            ),
        ),
    );
    let settings = settings_for(&path);
    assert!(
        settings.unknown_keys.is_empty(),
        "unrecognized keys: {:?}",
        settings.unknown_keys
    );

    let core_config = settings.get_core_config(0, 0).expect("should map");
    let rt = &core_config.network.routing_table;
    assert_eq!(rt.bootstrap_records, vec![record.to_owned()]);
    assert_eq!(
        rt.bootstrap_protocols,
        vec![
            veilid_core::VeilidConfigBootstrapProtocol::Udp,
            veilid_core::VeilidConfigBootstrapProtocol::Tcp
        ]
    );

    // The same keys are settable at runtime, as 'debug config set' does
    settings
        .set(
            "core.network.routing_table.bootstrap_records",
            "[\"one\",\"two\"]",
        )
        .expect("should set");
    settings
        .set(
            "core.network.routing_table.bootstrap_protocols",
            "[\"WSS\"]",
        )
        .expect("should set");
    let core_config = settings.get_core_config(0, 0).expect("should map");
    let rt = &core_config.network.routing_table;
    assert_eq!(
        rt.bootstrap_records,
        vec!["one".to_owned(), "two".to_owned()]
    );
    assert_eq!(
        rt.bootstrap_protocols,
        vec![veilid_core::VeilidConfigBootstrapProtocol::Wss]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The deprecated flag still parses as the records dump
pub fn test_dump_txt_record_alias_parses() {
    let args = crate::CmdlineArgs::try_parse_from(["veilid-server", "--dump-txt-record"])
        .expect("should parse");
    assert!(args.dump_bootstrap_records);

    let args = crate::CmdlineArgs::try_parse_from([
        "veilid-server",
        "--dump-bootstrap-records",
        "--bootstrap-hostname",
        "bootstrap.example",
    ])
    .expect("should parse");
    assert!(args.dump_bootstrap_records);
    assert_eq!(
        args.bootstrap_hostname.as_deref(),
        Some("bootstrap.example")
    );

    assert!(
        crate::CmdlineArgs::try_parse_from([
            "veilid-server",
            "--bootstrap-hostname",
            "bootstrap.example"
        ])
        .is_err(),
        "the hostname belongs to the records dump"
    );
}

/// Signing takes its lifetime and node lines from the command line, never a keypair
pub fn test_sign_bootstrap_payload_flags() {
    assert!(
        crate::CmdlineArgs::try_parse_from([
            "veilid-server",
            "--sign-bootstrap-payload",
            "node|AAAA"
        ])
        .is_err(),
        "the lifetime is required"
    );

    let args = crate::CmdlineArgs::try_parse_from([
        "veilid-server",
        "--sign-bootstrap-payload",
        "--bootstrap-payload-lifetime",
        "1y6mo",
        "--bootstrap-cache-ttl-hours",
        "12",
        "node|AAAA",
        "@nodes.txt",
    ])
    .expect("should parse");
    assert!(args.sign_bootstrap_payload);
    assert_eq!(args.bootstrap_payload_lifetime.as_deref(), Some("1y6mo"));
    assert_eq!(args.bootstrap_cache_ttl_hours, Some(12));
    assert_eq!(args.node_lines, ["node|AAAA", "@nodes.txt"]);

    assert!(
        crate::CmdlineArgs::try_parse_from(["veilid-server", "node|AAAA"]).is_err(),
        "node lines belong to signing"
    );
}

/// An '@FILE' argument stands for the node lines in the file
pub fn test_read_node_lines_expands_files() {
    let dir = test_dir("node-lines");
    let path = dir.join("nodes.txt");
    std::fs::write(&path, "node|AAAA\n\n  node|BBBB  \n").expect("should write");

    let lines = crate::read_node_lines(&["node|CCCC".to_owned(), format!("@{}", path.display())])
        .expect("should read");
    assert_eq!(lines, ["node|CCCC", "node|AAAA", "node|BBBB"]);
    assert!(crate::read_node_lines(&[]).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Which name the legacy record lines carry, from the operator or from reverse DNS
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
pub fn test_legacy_hostname_choice() {
    let v4: IpAddr = "203.0.113.5".parse().expect("should parse");
    let v6: IpAddr = "2001:db8::5".parse().expect("should parse");
    let names = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();

    // The operator's choice always wins, with a warning when nothing confirms it
    let (host, warning) = choose_legacy_hostname(&[v4], &names(&["a.example"]), Some("b.example"))
        .expect("should choose");
    assert_eq!(host, "b.example");
    assert!(warning.is_some());
    let (host, warning) = choose_legacy_hostname(&[v4], &names(&["a.example."]), Some("A.example"))
        .expect("should choose");
    assert_eq!(host, "A.example");
    assert!(warning.is_none());
    let (_, warning) =
        choose_legacy_hostname(&[v6], &[], Some("2001:DB8::5")).expect("should choose");
    assert!(warning.is_none());

    // One name every lookup agreed on, even when a lookup failed
    let (host, _) =
        choose_legacy_hostname(&[v4, v6], &names(&["a.example"]), None).expect("should choose");
    assert_eq!(host, "a.example");
    let (host, _) = choose_legacy_hostname(&[v4, v6], &names(&["a.example", "A.example."]), None)
        .expect("should choose");
    assert_eq!(host, "a.example");
    assert!(choose_legacy_hostname(&[v4, v6], &names(&["a.example", "b.example"]), None).is_err());

    // Without a name the lone address stands in, and two addresses need the operator
    let (host, _) = choose_legacy_hostname(&[v4], &[], None).expect("should choose");
    assert_eq!(host, "203.0.113.5");
    assert!(choose_legacy_hostname(&[v4, v6], &[], None).is_err());
}

#[cfg(not(feature = "mock-api"))]
mod live {
    use super::*;
    use std::net::{TcpListener, UdpSocket};
    use std::sync::{Arc, OnceLock};
    use tracing_subscriber::prelude::*;
    use veilid_core::tools::{shell_words, sleep};
    use veilid_core::*;

    const NETWORK_START_TIMEOUT_MS: u32 = 30_000;
    const POLL_MS: u32 = 250;
    /// RFC 2606: never resolves, so a bootstrap entry nothing can be learned from
    const UNRESOLVABLE_HOST: &str = "bootstrap.invalid";

    /// A namespace of its own per node, so the tests of one process never share a core slot
    fn unique_subnode() -> u16 {
        (TEST_SEQ.fetch_add(1, Ordering::AcqRel) % u32::from(u16::MAX)) as u16 + 1
    }

    async fn start(path: &Path, subnode: u16) -> VeilidAPI {
        // Before the first node, so a later timeout has a log to show
        let _ = core_log_path();
        let settings = settings_for(path);
        assert!(
            settings.unknown_keys.is_empty(),
            "test config has unrecognized keys: {:?}",
            settings.unknown_keys
        );
        let core_config = settings
            .get_core_config(subnode, 0)
            .expect("should map to a core config");
        let update_callback: UpdateCallback = Arc::new(|_| {});
        api_startup(update_callback, core_config)
            .await
            .expect("should start")
    }

    async fn wait_for_network(api: &VeilidAPI, port: u16) {
        let mut waited_ms = 0;
        while !api
            .get_state()
            .await
            .expect("should get state")
            .network
            .started
        {
            assert!(
                waited_ms < NETWORK_START_TIMEOUT_MS,
                "network never started on port {} after {} ms\nudp bindable now: {}, tcp bindable now: {}\n--- core log tail ---\n{}",
                port,
                waited_ms,
                UdpSocket::bind(("0.0.0.0", port)).is_ok(),
                TcpListener::bind(("0.0.0.0", port)).is_ok(),
                core_log_tail(60),
            );
            sleep(POLL_MS).await;
            waited_ms += POLL_MS;
        }
    }

    /// Core's own log, so a timeout assert can say what the node was doing. One file per test
    /// process (nextest gives each test its own), opened on first use and kept only if the test
    /// fails.
    fn core_log_path() -> &'static Path {
        static CORE_LOG: OnceLock<PathBuf> = OnceLock::new();
        CORE_LOG.get_or_init(|| {
            let path =
                std::env::temp_dir().join(format!("veilid-server-test-{}.log", std::process::id()));
            let file = std::fs::File::create(&path).expect("should make a log file");
            let (writer, guard) = tracing_appender::non_blocking(file);
            // The appender flushes on drop, so its guard has to outlive every node in the process
            Box::leak(Box::new(guard));
            let filter = VeilidLayerFilter::new_with_config(
                VeilidLayerFilterConfig::new()
                    .with_common_log_level(VeilidConfigLogLevel::Info)
                    .try_with_directives_string("net=debug,attach=debug,rtab=debug")
                    .expect("should parse directives"),
            );
            let layer = tracing_subscriber::fmt::Layer::new()
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(filter);
            let _ = tracing_subscriber::registry().with(layer).try_init();
            path
        })
    }

    /// How long the node took to bind, or None if it never did within the budget
    async fn network_start_delay(api: &VeilidAPI, budget_ms: u32) -> Option<u32> {
        let mut waited_ms = 0;
        loop {
            if api
                .get_state()
                .await
                .expect("should get state")
                .network
                .started
            {
                return Some(waited_ms);
            }
            if waited_ms >= budget_ms {
                return None;
            }
            sleep(POLL_MS).await;
            waited_ms += POLL_MS;
        }
    }

    /// Nothing failed, so the log has nothing to say
    fn discard_core_log() {
        let _ = std::fs::remove_file(core_log_path());
    }

    fn core_log_tail(lines: usize) -> String {
        let Ok(text) = std::fs::read_to_string(core_log_path()) else {
            return "(no core log)".to_owned();
        };
        let all: Vec<&str> = text.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }

    /// A port free on BOTH protocols right now, because the node binds it for UDP and TCP a
    /// moment later, and below every platform's ephemeral range (Linux 32768+, macOS and Windows
    /// 49152+): an ephemeral pick can be handed to any process's next outbound connection between
    /// this probe and the node's bind and then stays taken on TCP for that connection's life,
    /// while a node that loses its bind retries only every `network.bind_retry_ms`, longer than
    /// this test's timeout.
    fn free_port() -> u16 {
        let micros = Timestamp::now().as_u64();
        let base = 10_000 + ((u64::from(std::process::id()) ^ micros) % 22_000) as u16;
        for i in 0..64 {
            let port = base + i;
            let Ok(_udp) = UdpSocket::bind(("0.0.0.0", port)) else {
                continue;
            };
            // Held together: releasing the udp socket first would let another process take the port
            if TcpListener::bind(("0.0.0.0", port)).is_ok() {
                return port;
            }
        }
        panic!("no port free on both udp and tcp");
    }

    /// The node's own line, there once its PublicInternet dial info is
    async fn wait_for_node_line(api: &VeilidAPI) -> String {
        let mut waited_ms = 0;
        loop {
            let line = api
                .debug("bootstrapnode".to_owned())
                .await
                .expect("should run")
                .trim()
                .to_owned();
            if line.starts_with("node|") {
                return line;
            }
            assert!(
                waited_ms < NETWORK_START_TIMEOUT_MS,
                "no bootstrap node line after {} ms: {}",
                waited_ms,
                line
            );
            sleep(POLL_MS).await;
            waited_ms += POLL_MS;
        }
    }

    /// What the PublicInternet domain holds to answer bootstrap requests, as `debug dialinfo`
    /// reports it: `None`, or the payload's signing time, expiration, ttl and origin
    async fn held_bootstrap_payload(api: &VeilidAPI) -> String {
        let dialinfo = api.debug("dialinfo".to_owned()).await.expect("should run");
        let public_internet = dialinfo
            .split("PublicInternet:")
            .nth(1)
            .expect("dialinfo should list PublicInternet");
        public_internet
            .lines()
            .find_map(|line| line.trim().strip_prefix("Bootstrap Payload: "))
            .expect("dialinfo should report the bootstrap payload")
            .to_owned()
    }

    /// The node's own line, signed into a payload as the operator tooling does, is what the
    /// node holds to serve once its config carries the line. Serving it on the wire takes a node
    /// reachable on every protocol it listens on, which veilid-core's tests cover
    async fn configured_payload_is_held(bootstrap: &str) {
        let dir = test_dir("payload");
        let port = free_port();
        let subnode = unique_subnode();
        let signing_keypair =
            Crypto::generate_keypair(CRYPTO_KIND_VLD0).expect("should make a keypair");

        let path = write_config(&dir, &network_block(port, "            bootstrap: []"));
        let api = start(&path, subnode).await;
        api.attach().await.expect("should attach");
        wait_for_network(&api, port).await;
        let node_line = wait_for_node_line(&api).await;
        let keypairs_arg = format!("[{}]", signing_keypair);
        let payload_line = api
            .debug(shell_words::join([
                "bootstrappayload",
                "1y",
                "--keypairs",
                keypairs_arg.as_str(),
                node_line.as_str(),
            ]))
            .await
            .expect("should sign");
        let payload_line = payload_line.trim();
        assert!(
            payload_line.starts_with("2|"),
            "not a payload line: {}",
            payload_line
        );
        assert_eq!(held_bootstrap_payload(&api).await, "None");
        api.shutdown().await;

        // The same node, now configured with the line it signed
        let path = write_config(
            &dir,
            &network_block(
                port,
                &format!(
                    "{}\n            bootstrap_keys: ['{}']\n            bootstrap_records:\n                - '{}'",
                    bootstrap,
                    signing_keypair.key(),
                    payload_line
                ),
            ),
        );
        let api = start(&path, subnode).await;
        api.attach().await.expect("should attach");
        wait_for_network(&api, port).await;
        let held = held_bootstrap_payload(&api).await;
        assert!(
            held.starts_with("signed ") && held.contains(" expires 20"),
            "configured payload not held: {}",
            held
        );

        api.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        discard_core_log();
    }

    pub fn test_configured_payload_is_held() {
        block_on(async {
            configured_payload_is_held("            bootstrap: []").await;
        });
    }

    /// A bootstrap entry that cannot be resolved changes nothing about what the node holds
    pub fn test_configured_payload_is_held_beside_unreachable_bootstrap() {
        block_on(async {
            configured_payload_is_held(&format!(
                "            bootstrap: ['{}']",
                UNRESOLVABLE_HOST
            ))
            .await;
        });
    }

    /// The failure `free_port` exists to prevent, on demand. A node that loses either bind
    /// retries only every `network.bind_retry_ms` (10 s by default), so a port held for a whole
    /// test run shows up as `network never started` and nothing else. Holding UDP and holding TCP
    /// are separate cases because an ephemeral port the OS hands out for one says nothing about
    /// the other.
    async fn run_port_held_case(label: &str, hold_udp: bool, release_after_ms: u32) -> Option<u32> {
        let dir = test_dir(label);
        let port = free_port();
        let path = write_config(&dir, &network_block(port, "            bootstrap: []"));

        let mut udp_hold =
            hold_udp.then(|| UdpSocket::bind(("0.0.0.0", port)).expect("should hold udp"));
        let mut tcp_hold =
            (!hold_udp).then(|| TcpListener::bind(("0.0.0.0", port)).expect("should hold tcp"));

        let api = start(&path, unique_subnode()).await;
        api.attach().await.expect("should attach");

        let delay = if release_after_ms == u32::MAX {
            network_start_delay(&api, NETWORK_START_TIMEOUT_MS).await
        } else {
            // Nothing should have bound while the port was held
            assert_eq!(network_start_delay(&api, release_after_ms).await, None);
            udp_hold.take();
            tcp_hold.take();
            network_start_delay(&api, NETWORK_START_TIMEOUT_MS).await
        };

        api.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        discard_core_log();
        delay
    }

    /// Not a gate: it spends 30 s per held case waiting for something that must not happen.
    /// Run it with `cargo nextest run -p veilid-server --run-ignored all -E 'test(port_held)'`.
    pub fn test_port_held_stalls_network_start() {
        block_on(async {
            assert!(
                run_port_held_case("held-udp", true, u32::MAX)
                    .await
                    .is_none(),
                "a held udp port should stall the bind for the whole budget"
            );
            assert!(
                run_port_held_case("held-tcp", false, u32::MAX)
                    .await
                    .is_none(),
                "a held tcp port should stall the bind for the whole budget"
            );
            // Recovery waits for the next retry, so a longer-lived holder is fatal rather than slow
            let delay = run_port_held_case("released-tcp", false, 5_000)
                .await
                .expect("should bind once the port is free");
            assert!(delay >= 5_000, "bound too early to have waited for a retry");
        });
    }
}

#[cfg(not(feature = "mock-api"))]
use crate::tools::block_on;
#[cfg(not(feature = "mock-api"))]
use live::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_without_bootstrap_records() {
        test_config_without_bootstrap_records();
    }

    #[test]
    fn config_with_bootstrap_records() {
        test_config_with_bootstrap_records();
    }

    #[test]
    fn dump_txt_record_alias_parses() {
        test_dump_txt_record_alias_parses();
    }

    #[test]
    fn sign_bootstrap_payload_flags() {
        test_sign_bootstrap_payload_flags();
    }

    #[test]
    fn read_node_lines_expands_files() {
        test_read_node_lines_expands_files();
    }

    #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
    #[test]
    fn legacy_hostname_choice() {
        test_legacy_hostname_choice();
    }

    #[cfg(not(feature = "mock-api"))]
    #[test]
    fn configured_payload_is_held() {
        test_configured_payload_is_held();
    }

    #[cfg(not(feature = "mock-api"))]
    #[test]
    fn configured_payload_is_held_beside_unreachable_bootstrap() {
        test_configured_payload_is_held_beside_unreachable_bootstrap();
    }

    #[cfg(not(feature = "mock-api"))]
    #[test]
    #[ignore = "reproduction; ~90s of deliberate waiting"]
    fn port_held_stalls_network_start() {
        test_port_held_stalls_network_start();
    }
}
