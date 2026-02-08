use super::{Benchmark, BenchmarkContext, BenchmarkResult};
use async_trait::async_trait;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};
use veilid_core::*;

const COORD_PORT: u16 = 5152;
const APP_CALL_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT_SECS: u64 = 120;
const SIZES: [usize; 4] = [64, 256, 1024, 4096];
const ITERATIONS: usize = 10;

fn coordinator_addr() -> String {
    std::env::var("COORD_ADDR").unwrap_or_else(|_| "11.0.0.1".to_string())
}

fn elapsed_us(start: Instant) -> u128 {
    start.elapsed().as_micros()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Coordination message: APPCALL|node_id|route_blob_hex|timestamp
struct CoordMessage {
    node_id: String,
    route_blob_hex: String,
    timestamp_us: u128,
}

impl CoordMessage {
    fn encode(&self) -> String {
        format!(
            "APPCALL|{}|{}|{}\n",
            self.node_id, self.route_blob_hex, self.timestamp_us
        )
    }

    fn decode(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.trim().split('|').collect();
        if parts.len() == 4 && parts[0] == "APPCALL" {
            Some(CoordMessage {
                node_id: parts[1].to_string(),
                route_blob_hex: parts[2].to_string(),
                timestamp_us: parts[3].parse().ok()?,
            })
        } else {
            None
        }
    }
}

/// Writer (bootstrap node): creates a private route, serves coordination info via TCP.
/// The existing app_call_handler in main.rs echoes all calls.
pub struct AppCallWriter;

impl Default for AppCallWriter {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl Benchmark for AppCallWriter {
    fn name(&self) -> &str {
        "app_call_write"
    }

    fn category(&self) -> &str {
        "app_call"
    }

    async fn run(&self, ctx: &BenchmarkContext) -> Result<Vec<BenchmarkResult>, VeilidAPIError> {
        // Get own node id
        let state = ctx.api.get_state().await?;
        let own_node_id = state
            .network
            .node_ids
            .first()
            .ok_or_else(|| VeilidAPIError::Internal {
                message: "No node IDs available".to_string(),
            })?
            .clone();

        // Create private route
        let route_blob = ctx.api.new_private_route().await?;
        let route_blob_hex = hex_encode(&route_blob.blob);

        let timestamp_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();

        let coord_msg = CoordMessage {
            node_id: own_node_id.to_string(),
            route_blob_hex,
            timestamp_us,
        };
        let msg_bytes = coord_msg.encode();

        println!(
            "APP_CALL,[{}],writer_started,node_id={}",
            ctx.node_id, own_node_id
        );

        // Start TCP coordination server
        let listen_addr = format!("0.0.0.0:{}", COORD_PORT);
        let listener =
            TcpListener::bind(&listen_addr)
                .await
                .map_err(|e| VeilidAPIError::Internal {
                    message: format!("Failed to bind coordination server: {}", e),
                })?;

        println!(
            "APP_CALL,[{}],coordination_server_started,{}",
            ctx.node_id, listen_addr
        );

        let expected = super::expected_readers();
        let mut readers_served = 0u32;
        loop {
            match timeout(Duration::from_secs(IDLE_TIMEOUT_SECS), listener.accept()).await {
                Ok(Ok((mut stream, _addr))) => {
                    readers_served += 1;
                    if let Err(e) = stream.write_all(msg_bytes.as_bytes()).await {
                        println!("APP_CALL,[{}],write_error,{:?}", ctx.node_id, e);
                    }
                    let _ = stream.shutdown().await;
                    if expected.is_some_and(|n| readers_served >= n) {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    println!("APP_CALL,[{}],accept_error,{:?}", ctx.node_id, e);
                }
                Err(_) => {
                    break;
                }
            }
        }

        println!(
            "APP_CALL,[{}],server_done,readers_served={}",
            ctx.node_id, readers_served
        );

        // Writer returns empty results; it just serves coordination data
        Ok(Vec::new())
    }
}

/// Reader (normal/slow nodes): connects to writer, runs app_call benchmarks
/// using both direct NodeId and private route targets.
pub struct AppCallReader {
    pub timeout_secs: u64,
}

impl Default for AppCallReader {
    fn default() -> Self {
        Self { timeout_secs: 120 }
    }
}

#[async_trait]
impl Benchmark for AppCallReader {
    fn name(&self) -> &str {
        "app_call_read"
    }

    fn category(&self) -> &str {
        "app_call"
    }

    async fn run(&self, ctx: &BenchmarkContext) -> Result<Vec<BenchmarkResult>, VeilidAPIError> {
        let mut results = Vec::new();

        let coord_addr = format!("{}:{}", coordinator_addr(), COORD_PORT);
        println!(
            "APP_CALL,[{}],connecting_to_coordinator,{}",
            ctx.node_id, coord_addr
        );

        // Connect to coordination server with retries
        let mut stream = None;
        let deadline = Instant::now() + Duration::from_secs(self.timeout_secs);
        while Instant::now() < deadline {
            match TcpStream::connect(&coord_addr).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(_) => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        let stream = match stream {
            Some(s) => s,
            None => {
                println!(
                    "APP_CALL,[{}],timeout_connecting_to_coordinator",
                    ctx.node_id
                );
                return Ok(results);
            }
        };

        println!("APP_CALL,[{}],connected_to_coordinator", ctx.node_id);

        // Read coordination message
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        if let Err(e) = reader.read_line(&mut line).await {
            println!("APP_CALL,[{}],read_error,{:?}", ctx.node_id, e);
            return Ok(results);
        }

        let coord_msg = match CoordMessage::decode(&line) {
            Some(msg) => msg,
            None => {
                println!(
                    "APP_CALL,[{}],invalid_coord_message,{}",
                    ctx.node_id,
                    line.trim()
                );
                return Ok(results);
            }
        };

        // Parse target node id
        let target_node_id: NodeId =
            coord_msg
                .node_id
                .parse()
                .map_err(|e: VeilidAPIError| VeilidAPIError::Internal {
                    message: format!("Failed to parse NodeId: {}", e),
                })?;

        // Decode and import private route
        let route_blob_bytes =
            hex_decode(&coord_msg.route_blob_hex).ok_or_else(|| VeilidAPIError::Internal {
                message: "Failed to hex-decode route blob".to_string(),
            })?;
        let route_id = ctx.api.import_remote_private_route(route_blob_bytes)?;

        println!(
            "APP_CALL,[{}],targets_ready,node_id={},route_id={:?}",
            ctx.node_id, target_node_id, route_id
        );

        // Phase 1: Direct app_call via NodeId
        let direct_target = Target::NodeId(target_node_id);
        for &size in &SIZES {
            let message: Vec<u8> = (0..size).map(|j| j as u8).collect();

            // Warmup
            let _ = ctx
                .routing_context
                .app_call(direct_target.clone(), message.clone())
                .await;

            for i in 0..ITERATIONS {
                let start = Instant::now();
                let result = timeout(
                    APP_CALL_TIMEOUT,
                    ctx.routing_context
                        .app_call(direct_target.clone(), message.clone()),
                )
                .await;
                let duration_us = elapsed_us(start);

                let timed_out = match result {
                    Ok(Ok(_)) => false,
                    Ok(Err(e)) => {
                        println!(
                            "APP_CALL,[{}],direct_error,size={},iter={},err={:?}",
                            ctx.node_id, size, i, e
                        );
                        true
                    }
                    Err(_) => {
                        println!(
                            "APP_CALL,[{}],direct_timeout,size={},iter={}",
                            ctx.node_id, size, i
                        );
                        true
                    }
                };

                results.push(BenchmarkResult {
                    name: format!("app_call_direct_{}", size),
                    iteration: i,
                    duration_us,
                    bytes: Some(size),
                    timed_out,
                });
            }
        }

        // Phase 2: Route-based app_call via RouteId
        let route_target = Target::RouteId(route_id);
        for &size in &SIZES {
            let message: Vec<u8> = (0..size).map(|j| j as u8).collect();

            // Warmup
            let _ = ctx
                .routing_context
                .app_call(route_target.clone(), message.clone())
                .await;

            for i in 0..ITERATIONS {
                let start = Instant::now();
                let result = timeout(
                    APP_CALL_TIMEOUT,
                    ctx.routing_context
                        .app_call(route_target.clone(), message.clone()),
                )
                .await;
                let duration_us = elapsed_us(start);

                let timed_out = match result {
                    Ok(Ok(_)) => false,
                    Ok(Err(e)) => {
                        println!(
                            "APP_CALL,[{}],route_error,size={},iter={},err={:?}",
                            ctx.node_id, size, i, e
                        );
                        true
                    }
                    Err(_) => {
                        println!(
                            "APP_CALL,[{}],route_timeout,size={},iter={}",
                            ctx.node_id, size, i
                        );
                        true
                    }
                };

                results.push(BenchmarkResult {
                    name: format!("app_call_route_{}", size),
                    iteration: i,
                    duration_us,
                    bytes: Some(size),
                    timed_out,
                });
            }
        }

        Ok(results)
    }
}

pub fn for_node_type(node_type: &str) -> Vec<Box<dyn Benchmark>> {
    match node_type {
        "bootstrap" => vec![Box::new(AppCallWriter::default())],
        _ => vec![Box::new(AppCallReader::default())],
    }
}
