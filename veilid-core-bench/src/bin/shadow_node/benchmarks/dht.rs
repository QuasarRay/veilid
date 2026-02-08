use super::{Benchmark, BenchmarkContext, BenchmarkResult};
use async_trait::async_trait;
use std::future::Future;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};
use veilid_core::*;

const DHT_OP_TIMEOUT: Duration = Duration::from_secs(10);

fn elapsed_us(start: Instant) -> u128 {
    start.elapsed().as_micros()
}

// --- Local DHT write benchmark ---

pub struct DhtWriteBenchmark {
    pub sizes: Vec<usize>,
    pub iterations: usize,
}

impl Default for DhtWriteBenchmark {
    fn default() -> Self {
        Self {
            sizes: vec![64, 256, 1024, 4096],
            iterations: 10,
        }
    }
}

#[async_trait]
impl Benchmark for DhtWriteBenchmark {
    fn name(&self) -> &str {
        "dht_write"
    }

    fn category(&self) -> &str {
        "dht"
    }

    async fn run(&self, ctx: &BenchmarkContext) -> Result<Vec<BenchmarkResult>, VeilidAPIError> {
        let mut results = Vec::new();

        // Need enough subkeys: 1 warmup + iterations per size
        let subkeys_needed = self.sizes.len() * (1 + self.iterations);
        let schema = DHTSchema::dflt(subkeys_needed as u16)?;
        let record = ctx
            .routing_context
            .create_dht_record(CRYPTO_KIND_VLD0, schema, None)
            .await?;
        let key = record.key().clone();

        let mut subkey_index: u32 = 0;

        for size in &self.sizes {
            let data: Vec<u8> = (0..*size).map(|j| j as u8).collect();

            // Warmup: one untimed write
            ctx.routing_context
                .set_dht_value(key.clone(), subkey_index, data.clone(), None)
                .await?;
            subkey_index += 1;

            for i in 0..self.iterations {
                let start = Instant::now();
                let result = timeout(
                    DHT_OP_TIMEOUT,
                    ctx.routing_context.set_dht_value(
                        key.clone(),
                        subkey_index,
                        data.clone(),
                        None,
                    ),
                )
                .await;
                let duration_us = elapsed_us(start);
                subkey_index += 1;

                let timed_out = match result {
                    Ok(Ok(_)) => false,
                    Ok(Err(e)) => {
                        println!(
                            "DHT,[{}],write_error,size={},iter={},err={:?}",
                            ctx.node_id, size, i, e
                        );
                        true
                    }
                    Err(_) => {
                        println!(
                            "DHT,[{}],write_timeout,size={},iter={}",
                            ctx.node_id, size, i
                        );
                        true
                    }
                };

                results.push(BenchmarkResult {
                    name: format!("{}_{}", self.name(), size),
                    iteration: i,
                    duration_us,
                    bytes: Some(*size),
                    timed_out,
                });
            }
        }

        ctx.routing_context.close_dht_record(key.clone()).await?;
        ctx.routing_context.delete_dht_record(key).await?;

        Ok(results)
    }
}

// --- Cross-node DHT propagation benchmark ---

/// TCP port for cross-node coordination (separate from Veilid's 5150)
const COORD_PORT: u16 = 5151;
/// Returns the coordinator node's IP address (configurable via COORD_ADDR env var).
fn coordinator_addr() -> String {
    std::env::var("COORD_ADDR").unwrap_or_else(|_| "11.0.0.1".to_string())
}
/// Stop accepting readers after no new connection for this duration
const IDLE_TIMEOUT_SECS: u64 = 120;

/// Data sizes written to each subkey by the writer, read by the reader
const READ_SIZES: [usize; 4] = [64, 256, 1024, 4096];
/// Number of timed read iterations per subkey/size
const READ_ITERATIONS: usize = 10;

/// Retry parameters for DHT operations
const DHT_RETRY_COUNT: u32 = 10;
const DHT_RETRY_BACKOFF: Duration = Duration::from_secs(5);

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

/// Retries a DHT operation up to `max_retries` times with backoff.
/// Each attempt is wrapped in a timeout. Returns `Err(VeilidAPIError::Timeout)` if all retries fail.
async fn retry_dht_op<F, Fut, T>(
    op_name: &str,
    node_id: &str,
    max_retries: u32,
    backoff: Duration,
    op_timeout: Duration,
    f: F,
) -> Result<T, VeilidAPIError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, VeilidAPIError>>,
{
    for attempt in 0..=max_retries {
        match timeout(op_timeout, f()).await {
            Ok(Ok(val)) => return Ok(val),
            Ok(Err(e)) => {
                println!(
                    "DHT,[{}],{}_error,attempt={},err={:?}",
                    node_id, op_name, attempt, e
                );
                if attempt < max_retries {
                    sleep(backoff).await;
                }
            }
            Err(_) => {
                println!("DHT,[{}],{}_timeout,attempt={}", node_id, op_name, attempt);
                if attempt < max_retries {
                    sleep(backoff).await;
                }
            }
        }
    }
    Err(VeilidAPIError::Timeout)
}

pub struct DhtPropagationWriter;

impl Default for DhtPropagationWriter {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl Benchmark for DhtPropagationWriter {
    fn name(&self) -> &str {
        "dht_propagation_write"
    }

    fn category(&self) -> &str {
        "dht"
    }

    async fn run(&self, ctx: &BenchmarkContext) -> Result<Vec<BenchmarkResult>, VeilidAPIError> {
        let mut results = Vec::new();

        // Create DHT record with one subkey per size
        let schema = DHTSchema::dflt(READ_SIZES.len() as u16)?;
        let record = ctx
            .routing_context
            .create_dht_record(CRYPTO_KIND_VLD0, schema, None)
            .await?;
        let key = record.key().clone();

        // Write each subkey with its corresponding size
        for (subkey, &size) in READ_SIZES.iter().enumerate() {
            let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let start = Instant::now();
            let result = timeout(
                DHT_OP_TIMEOUT,
                ctx.routing_context
                    .set_dht_value(key.clone(), subkey as u32, data, None),
            )
            .await;
            let write_duration = start.elapsed().as_micros();

            let timed_out = match result {
                Ok(Ok(_)) => false,
                Ok(Err(e)) => {
                    println!(
                        "DHT,[{}],write_local_error,size={},err={:?}",
                        ctx.node_id, size, e
                    );
                    true
                }
                Err(_) => {
                    println!("DHT,[{}],write_local_timeout,size={}", ctx.node_id, size);
                    true
                }
            };

            results.push(BenchmarkResult {
                name: format!("dht_write_local_{}", size),
                iteration: 0,
                duration_us: write_duration,
                bytes: Some(size),
                timed_out,
            });
        }

        let key_str = key.to_string();
        let publish_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();

        println!("DHT,[{}],dht_key_published,{}", ctx.node_id, key_str);

        // Start TCP coordination server
        let listen_addr = format!("0.0.0.0:{}", COORD_PORT);
        let listener =
            TcpListener::bind(&listen_addr)
                .await
                .map_err(|e| VeilidAPIError::Internal {
                    message: format!("Failed to bind coordination server: {}", e),
                })?;

        println!(
            "DHT,[{}],coordination_server_started,{}",
            ctx.node_id, listen_addr
        );

        let coord_msg = CoordMessage {
            dht_key: key_str,
            timestamp_us: publish_time,
        };
        let msg_bytes = coord_msg.encode();

        // Serve all connecting readers until idle timeout or expected count reached
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

        // Do NOT close/delete the DHT record here. Readers are still running
        // their multi-size read benchmarks and need the record to remain
        // available in the DHT. The record will expire naturally.

        Ok(results)
    }
}

pub struct DhtPropagationReader {
    pub timeout_secs: u64,
}

impl Default for DhtPropagationReader {
    fn default() -> Self {
        Self { timeout_secs: 120 }
    }
}

#[async_trait]
impl Benchmark for DhtPropagationReader {
    fn name(&self) -> &str {
        "dht_propagation_read"
    }

    fn category(&self) -> &str {
        "dht"
    }

    async fn run(&self, ctx: &BenchmarkContext) -> Result<Vec<BenchmarkResult>, VeilidAPIError> {
        let mut results = Vec::new();

        let coord_addr = format!("{}:{}", coordinator_addr(), COORD_PORT);
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
            println!("DHT,[{}],read_error,{:?}", ctx.node_id, e);
            return Ok(results);
        }

        let coord_msg = match CoordMessage::decode(&line) {
            Some(msg) => msg,
            None => {
                println!(
                    "DHT,[{}],invalid_coord_message,{}",
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
            "DHT,[{}],received_dht_key,{}",
            ctx.node_id, coord_msg.dht_key
        );

        // Open the remote DHT record with retries
        let start = Instant::now();

        let rc = ctx.routing_context.clone();
        let k = key.clone();
        let _record = retry_dht_op(
            "open_dht_record",
            &ctx.node_id,
            DHT_RETRY_COUNT,
            DHT_RETRY_BACKOFF,
            DHT_OP_TIMEOUT,
            || {
                let rc = rc.clone();
                let k = k.clone();
                async move { rc.open_dht_record(k, None).await }
            },
        )
        .await;

        let _record = match _record {
            Ok(r) => r,
            Err(e) => {
                println!("DHT,[{}],dht_open_failed,{:?}", ctx.node_id, e);
                return Ok(results);
            }
        };
        let open_duration = start.elapsed().as_micros();

        // Initial propagation read (subkey 0) with retries
        let read_start = Instant::now();
        let rc = ctx.routing_context.clone();
        let k = key.clone();
        let value = retry_dht_op(
            "get_dht_value",
            &ctx.node_id,
            DHT_RETRY_COUNT,
            DHT_RETRY_BACKOFF,
            DHT_OP_TIMEOUT,
            || {
                let rc = rc.clone();
                let k = k.clone();
                async move { rc.get_dht_value(k, 0, true).await }
            },
        )
        .await;

        let value = match value {
            Ok(v) => v,
            Err(e) => {
                println!("DHT,[{}],dht_read_failed,{:?}", ctx.node_id, e);
                ctx.routing_context.close_dht_record(key).await.ok();
                return Ok(results);
            }
        };
        let read_duration = read_start.elapsed().as_micros();

        let read_end_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();

        let propagation_time = if coord_msg.timestamp_us > 0 {
            read_end_timestamp.saturating_sub(coord_msg.timestamp_us)
        } else {
            0
        };

        let data_len = value.as_ref().map(|v| v.data().len()).unwrap_or(0);

        println!(
            "DHT,[{}],dht_open_duration,{}us",
            ctx.node_id, open_duration
        );
        println!(
            "DHT,[{}],dht_read_duration,{}us",
            ctx.node_id, read_duration
        );
        println!(
            "DHT,[{}],dht_propagation_time,{}us",
            ctx.node_id, propagation_time
        );

        results.push(BenchmarkResult {
            name: "dht_open_remote".to_string(),
            iteration: 0,
            duration_us: open_duration,
            bytes: None,
            timed_out: false,
        });

        results.push(BenchmarkResult {
            name: "dht_read_remote".to_string(),
            iteration: 0,
            duration_us: read_duration,
            bytes: Some(data_len),
            timed_out: false,
        });

        results.push(BenchmarkResult {
            name: "dht_propagation_total".to_string(),
            iteration: 0,
            duration_us: propagation_time,
            bytes: Some(data_len),
            timed_out: false,
        });

        // Multi-size timed reads: iterate over each subkey/size
        for (subkey, &size) in READ_SIZES.iter().enumerate() {
            // Warmup: one untimed read per subkey
            let _ = ctx
                .routing_context
                .get_dht_value(key.clone(), subkey as u32, true)
                .await;

            // Timed iterations
            for i in 0..READ_ITERATIONS {
                let iter_start = Instant::now();
                let read_result = timeout(
                    DHT_OP_TIMEOUT,
                    ctx.routing_context
                        .get_dht_value(key.clone(), subkey as u32, true),
                )
                .await;
                let duration_us = iter_start.elapsed().as_micros();

                let timed_out = match read_result {
                    Ok(Ok(_)) => false,
                    Ok(Err(e)) => {
                        println!(
                            "DHT,[{}],read_iter_error,size={},iter={},err={:?}",
                            ctx.node_id, size, i, e
                        );
                        true
                    }
                    Err(_) => {
                        println!(
                            "DHT,[{}],read_iter_timeout,size={},iter={}",
                            ctx.node_id, size, i
                        );
                        true
                    }
                };

                results.push(BenchmarkResult {
                    name: format!("dht_read_remote_{}", size),
                    iteration: i,
                    duration_us,
                    bytes: Some(size),
                    timed_out,
                });
            }
        }

        ctx.routing_context.close_dht_record(key).await?;

        Ok(results)
    }
}

// --- Public API ---

pub fn for_node_type(node_type: &str) -> Vec<Box<dyn Benchmark>> {
    let mut benchmarks: Vec<Box<dyn Benchmark>> = vec![Box::new(DhtWriteBenchmark::default())];
    match node_type {
        "bootstrap" => benchmarks.push(Box::new(DhtPropagationWriter::default())),
        _ => benchmarks.push(Box::new(DhtPropagationReader::default())),
    }
    benchmarks
}
