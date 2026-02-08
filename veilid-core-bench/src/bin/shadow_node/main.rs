#![recursion_limit = "512"]

mod benchmarks;
use std::{env, path::Path, sync::Arc};

use benchmarks::{all_benchmarks, BenchmarkContext};
use tokio::fs;
use tokio::sync::{mpsc, Mutex};
use veilid_core::{
    api_startup, AttachmentState, VeilidAPI, VeilidAppCall, VeilidConfig, VeilidConfigNetwork,
    VeilidConfigProtectedStore, VeilidConfigProtocol, VeilidConfigRoutingTable, VeilidConfigTCP,
    VeilidConfigTableStore, VeilidConfigUDP, VeilidConfigWS, VeilidUpdate, VeilidValueChange,
};
mod output;

fn build_config(
    node_id: &str,
    _node_type: &str,
    listen_addr: &str,
    data_dir: &Path,
) -> VeilidConfig {
    let bootstrap = vec![
        "udp://11.0.0.1:5150".to_string(),
        "udp://11.0.0.2:5150".to_string(),
        "udp://11.0.0.3:5150".to_string(),
    ];

    VeilidConfig {
        program_name: "shadow_node".into(),
        namespace: format!("shadow_{}", node_id),
        protected_store: VeilidConfigProtectedStore {
            always_use_insecure_storage: true,
            directory: data_dir.join("protected").to_string_lossy().into(),
            ..Default::default()
        },
        table_store: VeilidConfigTableStore {
            directory: data_dir.join("table").to_string_lossy().into(),
            ..Default::default()
        },
        network: VeilidConfigNetwork {
            connection_initial_timeout_ms: 10000,
            upnp: false,
            detect_address_changes: Some(false),
            restricted_nat_retries: 0,
            network_key_password: Some("shadow-benchmark-network".to_string()),
            routing_table: VeilidConfigRoutingTable {
                bootstrap,
                bootstrap_keys: vec![],
                limit_over_attached: 64,
                limit_fully_attached: 32,
                limit_attached_strong: 16,
                limit_attached_good: 8,
                limit_attached_weak: 4,
                ..Default::default()
            },
            protocol: VeilidConfigProtocol {
                udp: VeilidConfigUDP {
                    enabled: true,
                    socket_pool_size: 16,
                    listen_address: format!("{}:5150", listen_addr),
                    public_address: Some(format!("{}:5150", listen_addr)),
                },
                tcp: VeilidConfigTCP {
                    connect: true,
                    listen: true,
                    max_connections: 32,
                    listen_address: format!("{}:5150", listen_addr),
                    public_address: Some(format!("{}:5150", listen_addr)),
                },
                ws: VeilidConfigWS {
                    connect: false,
                    listen: false,
                    max_connections: 0,
                    listen_address: String::new(),
                    path: String::new(),
                    url: None,
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn app_call_handler(
    api: VeilidAPI,
    mut rx: mpsc::UnboundedReceiver<VeilidAppCall>,
    node_id: String,
) {
    while let Some(call) = rx.recv().await {
        let message = call.message().to_vec();
        let call_id = call.id();

        println!(
            "[{}] APPCALL: received {} bytes, call_id={:?}, sender={:?}",
            node_id,
            message.len(),
            call_id,
            call.sender()
        );

        match api.app_call_reply(call_id, message.clone()).await {
            Ok(()) => {
                println!(
                    "[{}] APPCALL: replied with {} bytes",
                    node_id,
                    message.len()
                );
            }
            Err(e) => {
                println!("[{}] APPCALL: reply error: {:?}", node_id, e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let node_id = env::var("SHADOW_NODE_ID").unwrap_or_else(|_| "0".to_string());
    let node_type = env::var("NODE_TYPE").unwrap_or_else(|_| "normal".to_string());
    let listen_addr = env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());

    println!("[{}] Starting as {} on {}", node_id, node_type, listen_addr);
    let tmp_dir = tempfile::TempDir::new().expect("Failed to create tmp_dir");
    let data_dir = tmp_dir.path().join(&node_id);
    let _ = fs::create_dir_all(&data_dir).await;
    println!("[{}] Cleaned up data directory: {:?}", node_id, data_dir);

    let (app_call_tx, app_call_rx) = mpsc::unbounded_channel::<VeilidAppCall>();
    let (dht_watch_tx, dht_watch_rx) = mpsc::unbounded_channel::<VeilidValueChange>();

    let node_id_for_callback = node_id.clone();

    let update_callback = Arc::new(move |update: VeilidUpdate| match &update {
        VeilidUpdate::Log(log) => {
            eprintln!(
                "[{}] LOG[{:?}]: {}",
                node_id_for_callback, log.log_level, log.message
            );
        }
        VeilidUpdate::Attachment(attachment) => {
            println!(
                "[{}] ATTACHMENT: state={:?} public_internet_ready={} local_network_ready={}",
                node_id_for_callback,
                attachment.state,
                attachment.public_internet_ready,
                attachment.local_network_ready
            );
        }
        VeilidUpdate::Network(network) => {
            println!(
                "[{}] NETWORK: started={} bps_down={} bps_up={} peers={}",
                node_id_for_callback,
                network.started,
                network.bps_down,
                network.bps_up,
                network.peers.len()
            );
        }
        VeilidUpdate::Config(config) => {
            println!("[{}] CONFIG: config changed", node_id_for_callback);
            let _ = config;
        }
        VeilidUpdate::RouteChange(route) => {
            println!("[{}] ROUTE_CHANGE: {:?}", node_id_for_callback, route);
        }
        VeilidUpdate::AppCall(call) => {
            let _ = app_call_tx.send((**call).clone());
        }
        VeilidUpdate::AppMessage(msg) => {
            println!(
                "[{}] APP_MESSAGE: {} bytes from {:?}",
                node_id_for_callback,
                msg.message().len(),
                msg.sender()
            );
        }
        VeilidUpdate::ValueChange(change) => {
            let _ = dht_watch_tx.send(change.as_ref().clone());
        }
        _ => {}
    });

    let config = build_config(&node_id, &node_type, &listen_addr, &data_dir);
    let api = api_startup(update_callback, config).await?;

    let api_clone = api.clone();
    let node_id_clone = node_id.clone();
    let _app_call_handler = tokio::spawn(async move {
        app_call_handler(api_clone, app_call_rx, node_id_clone).await;
    });

    api.attach().await?;

    // Configurable attachment and peer requirements
    let min_attachment_str = env::var("MIN_ATTACHMENT").unwrap_or_else(|_| "good".to_string());
    let min_peers: usize = env::var("MIN_PEERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let stabilization_secs: u64 = 180;

    let min_attachment = match min_attachment_str.as_str() {
        "weak" => AttachmentState::AttachedWeak,
        "strong" => AttachmentState::AttachedStrong,
        "full" => AttachmentState::FullyAttached,
        _ => AttachmentState::AttachedGood,
    };

    fn attachment_rank(state: &AttachmentState) -> u8 {
        match state {
            AttachmentState::AttachedWeak => 1,
            AttachmentState::AttachedGood => 2,
            AttachmentState::AttachedStrong => 3,
            AttachmentState::FullyAttached => 4,
            AttachmentState::OverAttached => 5,
            _ => 0,
        }
    }

    println!(
        "[{}] Waiting for attachment>={:?} and peers>={}...",
        node_id, min_attachment, min_peers
    );
    let start = std::time::Instant::now();
    let mut last_status_time = start;
    let mut criteria_met = false;
    while start.elapsed().as_secs() < 300 {
        if let Ok(state) = api.get_state().await {
            let cur_attachment = &state.attachment.state;
            let cur_peers = state.network.peers.len();

            if attachment_rank(cur_attachment) >= attachment_rank(&min_attachment)
                && cur_peers >= min_peers
            {
                println!(
                    "[{}] Attachment criteria met: state={:?} peers={}",
                    node_id, cur_attachment, cur_peers
                );
                criteria_met = true;
                break;
            }

            if last_status_time.elapsed().as_secs() >= 10 {
                println!(
                    "[{}] STATUS: attachment={:?} network_started={} peers={} (need {:?}, {} peers)",
                    node_id,
                    cur_attachment,
                    state.network.started,
                    cur_peers,
                    min_attachment,
                    min_peers
                );
                last_status_time = std::time::Instant::now();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    if !criteria_met {
        println!(
            "[{}] WARNING: Timeout waiting for attachment criteria after 300s",
            node_id
        );
    }

    // Stabilization period for DHT routing tables to settle
    println!(
        "[{}] Waiting {}s for DHT stabilization...",
        node_id, stabilization_secs
    );
    tokio::time::sleep(std::time::Duration::from_secs(stabilization_secs)).await;

    // Stagger benchmark start times to avoid flooding the DHT
    // Parse numeric suffix from node_id (e.g., "node42" -> 42); bootstrap nodes start first
    let stagger_index: u64 = node_id
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    let stagger_ms = stagger_index * 100;
    if stagger_ms > 0 {
        println!(
            "[{}] Staggering benchmark start by {}ms",
            node_id, stagger_ms
        );
        tokio::time::sleep(std::time::Duration::from_millis(stagger_ms)).await;
    }

    println!("[{}] Network ready, starting benchmarks...", node_id);

    let ctx = BenchmarkContext {
        api: api.clone(),
        routing_context: api.routing_context()?,
        node_id: node_id.clone(),
        dht_watch_rx: Arc::new(Mutex::new(dht_watch_rx)),
    };

    let mut report = output::BenchmarkReport::new(&node_id);

    for bench in all_benchmarks(&node_type) {
        let results = bench.run(&ctx).await?;
        for r in results {
            report.add(&r.name, bench.category(), &r);
            println!(
                "BENCH,[{}],{},{},{}us",
                node_id, r.name, r.iteration, r.duration_us
            );
        }
    }

    report.print_summary();
    report.save(Path::new("results.json"))?;

    api.detach().await?;
    api.shutdown().await;
    Ok(())
}
