use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc::UnboundedReceiver, Mutex};
use veilid_core::{RoutingContext, VeilidAPI, VeilidAPIError, VeilidValueChange};
mod app_call;
mod app_message;
mod dht;
mod dht_watch;

#[async_trait]
pub trait Benchmark: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> &str;
    async fn run(&self, ctx: &BenchmarkContext) -> Result<Vec<BenchmarkResult>, VeilidAPIError>;
}

pub struct BenchmarkResult {
    pub name: String,
    pub iteration: usize,
    pub duration_us: u128,
    pub bytes: Option<usize>,
    pub timed_out: bool,
}

pub struct BenchmarkContext {
    #[allow(dead_code)]
    pub api: VeilidAPI,
    pub routing_context: RoutingContext,
    pub node_id: String,
    pub dht_watch_rx: Arc<Mutex<UnboundedReceiver<VeilidValueChange>>>,
}

pub fn all_benchmarks(node_type: &str) -> Vec<Box<dyn Benchmark>> {
    let mut benchmarks: Vec<Box<dyn Benchmark>> = Vec::new();
    benchmarks.extend(dht::for_node_type(node_type));
    benchmarks.extend(app_call::for_node_type(node_type));
    benchmarks.extend(app_message::for_node_type(node_type));
    benchmarks.extend(dht_watch::for_node_type(node_type));
    benchmarks
}

/// Returns the expected number of reader nodes from the EXPECTED_READERS env var.
/// Coordination servers use this to exit immediately after serving all readers
/// instead of waiting for the idle timeout, which would delay subsequent benchmarks.
pub fn expected_readers() -> Option<u32> {
    std::env::var("EXPECTED_READERS")
        .ok()
        .and_then(|s| s.parse().ok())
}
