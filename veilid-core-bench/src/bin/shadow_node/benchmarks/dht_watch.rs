use super::{Benchmark, BenchmarkContext, BenchmarkResult};
use async_trait::async_trait;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};
use veilid_core::*;

pub struct DhtWatchWriterBenchmark {
    pub size: usize,
}

impl Default for DhtWatchWriterBenchmark {
    fn default() -> Self {
        Self { size: 4096 }
    }
}

#[async_trait]
impl Benchmark for DhtWatchWriterBenchmark {
    fn name(&self) -> &str {
        "dht_watch_write"
    }

    fn category(&self) -> &str {
        "dht"
    }
    async fn run(&self, ctx: &BenchmarkContext) -> Result<Vec<BenchmarkResult>, VeilidAPIError> {
        let schema = DHTSchema::dflt(1)?;
        let record = ctx
            .routing_context
            .create_dht_record(CRYPTO_KIND_VLD0, schema, None)
            .await?;
        let key = record.key().clone();
        let data: Vec<u8> = (0..self.size).map(|j| j as u8).collect();

        ctx.routing_context
            .set_dht_value(key.clone(), 0, data.clone(), None)
            .await?;

        let key_str = key.to_string();
        let publish_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();

        println!("DHT Watch,[{}],dht_key_published,{}", ctx.node_id, key_str);

        // Start TCP coordination server
        let listen_addr = format!("0.0.0.0:{}", COORD_PORT_WATCH);
        let listener =
            TcpListener::bind(&listen_addr)
                .await
                .map_err(|e| VeilidAPIError::Internal {
                    message: format!("Failed to bind coordination server: {}", e),
                })?;

        println!(
            "DHT Watch,[{}],coordination_server_started,{}",
            ctx.node_id, listen_addr
        );

        let coord_msg = CoordMessage {
            dht_key: key_str,
            timestamp_us: publish_time,
        };
        let msg_bytes = coord_msg.encode();

        // Receive confirmation from readers that they need the DHT key
        let expected = super::expected_readers();
        let mut readers_served = 0u32;
        loop {
            match timeout(Duration::from_secs(IDLE_TIMEOUT_SECS), listener.accept()).await {
                Ok(Ok((mut stream, _addr))) => {
                    readers_served += 1;
                    if let Err(e) = stream.write_all(msg_bytes.as_bytes()).await {
                        println!("DHT,[{}],write_error,{:?}", ctx.node_id, e);
                    }
                    let _ = stream.shutdown().await;
                    if expected.is_some_and(|n| readers_served >= n) {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    println!("DHT,[{}],accept_error,{:?}", ctx.node_id, e);
                }
                Err(_) => {
                    // No new connection for IDLE_TIMEOUT_SECS, done serving
                    break;
                }
            }
        }

        println!(
            "DHT,[{}],server_done,readers_served={}",
            ctx.node_id, readers_served
        );
        let listen_addr = format!("0.0.0.0:{}", COORD_PORT_WATCH_FEEDBACK);
        let listener =
            TcpListener::bind(&listen_addr)
                .await
                .map_err(|e| VeilidAPIError::Internal {
                    message: format!("Failed to bind coordination server: {}", e),
                })?;
        let mut watching_nodes = 0u32;
        loop {
            match timeout(Duration::from_secs(IDLE_TIMEOUT_SECS), listener.accept()).await {
                Ok(Ok((stream, _addr))) => {
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    if let Err(e) = reader.read_line(&mut line).await {
                        println!("DHT,[{}],read_error,{:?}", ctx.node_id, e);
                    }

                    if let Some(feedback_msg) = FeedbackMessage::decode(&line) {
                        if feedback_msg.success {
                            watching_nodes += 1;
                        }
                    };
                    if expected.is_some_and(|n| watching_nodes >= n) {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    println!("DHT,[{}],accept_error,{:?}", ctx.node_id, e);
                }
                Err(_) => {
                    // No new connection for IDLE_TIMEOUT_SECS, done serving
                    break;
                }
            }
        }

        println!("{} nodes are now watching the dht record", watching_nodes);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let mut data = ts.to_le_bytes().to_vec(); // 8 Bytes
        data.resize(self.size, 0u8);
        ctx.routing_context
            .set_dht_value(key.clone(), 0, data.clone(), None)
            .await?;

        Ok(Vec::new())
    }
}

pub struct DhtWatchReaderBenchmark {
    pub timeout_secs: u64,
}

impl Default for DhtWatchReaderBenchmark {
    fn default() -> Self {
        Self { timeout_secs: 120 }
    }
}

#[async_trait]
impl Benchmark for DhtWatchReaderBenchmark {
    fn name(&self) -> &str {
        "dht_watch_read"
    }

    fn category(&self) -> &str {
        "dht"
    }
    async fn run(&self, ctx: &BenchmarkContext) -> Result<Vec<BenchmarkResult>, VeilidAPIError> {
        let mut results = Vec::new();

        let coord_addr = format!("{}:{}", coordinator_addr(), COORD_PORT_WATCH);
        println!(
            "DHT,[{}],connecting_to_coordinator,{}",
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
                println!("DHT,[{}],timeout_connecting_to_coordinator", ctx.node_id);
                return Ok(results);
            }
        };

        println!("DHT,[{}],connected_to_coordinator", ctx.node_id);

        // Read coordination message
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        if let Err(e) = reader.read_line(&mut line).await {
            println!("DHT_watch,[{}],read_error,{:?}", ctx.node_id, e);
            return Ok(results);
        }

        let coord_msg = match CoordMessage::decode(&line) {
            Some(msg) => msg,
            None => {
                println!(
                    "DHT_watch,[{}],invalid_coord_message,{}",
                    ctx.node_id,
                    line.trim()
                );
                return Ok(results);
            }
        };

        let key: RecordKey = coord_msg
            .dht_key
            .parse()
            .map_err(|e| VeilidAPIError::Internal {
                message: format!("Failed to parse DHT key: {}", e),
            })?;

        println!(
            "DHT_watch,[{}],received_dht_key,{}",
            ctx.node_id, coord_msg.dht_key
        );
        // Open the DHT record with retries
        let mut opened = false;
        for attempt in 0..10 {
            match ctx.routing_context.open_dht_record(key.clone(), None).await {
                Ok(_) => {
                    opened = true;
                    break;
                }
                Err(e) => {
                    println!(
                        "DHT_watch,[{}],open_retry,attempt={},error={}",
                        ctx.node_id, attempt, e
                    );
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }
        if !opened {
            println!("DHT_watch,[{}],open_failed", ctx.node_id);
            return Ok(results);
        }

        let initial_data = ctx
            .routing_context
            .get_dht_value(key.clone(), 0, true)
            .await
            .ok()
            .flatten()
            .map(|v| v.data().to_vec());

        // Set up DHT watch with retries — may fail if route assembly
        // isn't ready yet ("unable to assemble route until we have
        // published peerinfo").
        let mut watch_active = false;
        for attempt in 0..10 {
            match ctx
                .routing_context
                .watch_dht_values(key.clone(), None, None, None)
                .await
            {
                Ok(active) => {
                    println!(
                        "DHT_watch,[{}],watch_result,attempt={},active={}",
                        ctx.node_id, attempt, active
                    );
                    watch_active = active;
                    break;
                }
                Err(e) => {
                    println!(
                        "DHT_watch,[{}],watch_retry,attempt={},error={}",
                        ctx.node_id, attempt, e
                    );
                    sleep(Duration::from_secs(3)).await;
                }
            }
        }

        // Tell the writer we are ready; after this the writer will update
        // the DHT value with timestamped data.
        let coord_addr = format!("{}:{}", coordinator_addr(), COORD_PORT_WATCH_FEEDBACK);
        let feedback_msg = FeedbackMessage {
            success: watch_active,
        };
        let msg_bytes = feedback_msg.encode();
        if let Ok(mut stream) = TcpStream::connect(coord_addr).await {
            let _ = stream.write_all(msg_bytes.as_bytes()).await;
            let _ = stream.shutdown().await;
        }

        if !watch_active {
            println!("DHT_watch,[{}],watch_not_active,skipping", ctx.node_id);
            return Ok(results);
        }

        // Drain all ValueChange events that accumulated during open/watch/
        // feedback — we only want to measure events from the writer's update.
        let mut dht_watch_rx = ctx.dht_watch_rx.lock().await;
        while dht_watch_rx.try_recv().is_ok() {}

        // Start the timer right before waiting for the writer's update.
        let start = Instant::now();

        match timeout(Duration::from_secs(120), dht_watch_rx.recv()).await {
            Ok(Some(_change)) => {
                let latency = start.elapsed();
                // Verify the value actually changed
                let new_data = ctx
                    .routing_context
                    .get_dht_value(key.clone(), 0, true)
                    .await
                    .ok()
                    .flatten()
                    .map(|v| v.data().to_vec());

                let changed = match (&initial_data, &new_data) {
                    (Some(old), Some(new)) => old != new,
                    (None, Some(_)) => true,
                    _ => false,
                };

                if changed {
                    results.push(BenchmarkResult {
                        name: "dht_watch_value_change".to_string(),
                        iteration: 1,
                        duration_us: latency.as_micros(),
                        bytes: new_data.map(|d| d.len()),
                        timed_out: false,
                    });
                }
            }
            Ok(None) => {}
            Err(_) => {
                results.push(BenchmarkResult {
                    name: "dht_watch_value_change".to_string(),
                    iteration: 1,
                    duration_us: 0,
                    bytes: None,
                    timed_out: true,
                });
            }
        }

        Ok(results)
    }
}

/// TCP port for cross-node coordination (separate from Veilid's 5150)
const COORD_PORT_WATCH: u16 = 5154;
const COORD_PORT_WATCH_FEEDBACK: u16 = 5155;

/// Stop accepting readers after no new connection for this duration
const IDLE_TIMEOUT_SECS: u64 = 120;

// Feedback message from readers that they have activated the Watch

struct FeedbackMessage {
    success: bool,
}

impl FeedbackMessage {
    fn encode(&self) -> String {
        if self.success {
            "true".to_string()
        } else {
            "false".to_string()
        }
    }
    fn decode(line: &str) -> Option<Self> {
        match line.trim() {
            "true" => Some(FeedbackMessage { success: true }),
            "false" => Some(FeedbackMessage { success: false }),
            _ => None,
        }
    }
}

/// Coordination message sent from writer to readers
struct CoordMessage {
    dht_key: String,
    timestamp_us: u128,
}

impl CoordMessage {
    fn encode(&self) -> String {
        format!("KEY|{}|{}\n", self.dht_key, self.timestamp_us)
    }

    fn decode(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.trim().split('|').collect();
        if parts.len() == 3 && parts[0] == "KEY" {
            Some(CoordMessage {
                dht_key: parts[1].to_string(),
                timestamp_us: parts[2].parse().ok()?,
            })
        } else {
            None
        }
    }
}

/// Returns the coordinator node's IP address (configurable via COORD_ADDR env var).
fn coordinator_addr() -> String {
    std::env::var("COORD_ADDR").unwrap_or_else(|_| "11.0.0.1".to_string())
}

// --- Public API ---

pub fn for_node_type(node_type: &str) -> Vec<Box<dyn Benchmark>> {
    match node_type {
        "bootstrap" => return vec![Box::new(DhtWatchWriterBenchmark::default())],
        _ => return vec![Box::new(DhtWatchReaderBenchmark::default())],
    }
}
