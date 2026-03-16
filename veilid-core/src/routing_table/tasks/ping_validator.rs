use super::*;

use futures_util::future::{select, Either};
use futures_util::stream::{FuturesUnordered, StreamExt};
use stop_token::future::FutureExt as _;

impl_veilid_log_facility!("rtab");

/// Number of consecutive successful pings required to consider a route tested
const ROUTE_TEST_PING_COUNT: usize = 3;

/////////////////////////////////////
// Priority Groups

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PingValidationGroup {
    RouteTest = 0,
    Keepalive = 1,
    Reliability = 2,
}

impl PingValidationGroup {
    fn max_parallel(&self) -> usize {
        match self {
            Self::RouteTest => 4,
            Self::Keepalive => 4,
            Self::Reliability => 16,
        }
    }
}

/////////////////////////////////////
// Ping Validation Entry Types

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PingValidationKey {
    Destination(Destination),
    RouteTest {
        route_id: RouteId,
        ping_index: usize,
    },
}

/// Callback invoked when a ping completes.
/// Receives the registry and the ping result.
/// Returns follow-up entries to re-enqueue (e.g., next ping in a route test chain).
pub type PingCompletionCallback = Box<
    dyn FnOnce(
            VeilidComponentRegistry,
            Result<NetworkResult<Answer<StatusResult>>, RPCError>,
        ) -> Vec<PingValidationEntry>
        + Send
        + 'static,
>;

pub struct PingValidationEntry {
    pub group: PingValidationGroup,
    pub priority: usize, // 0 = highest
    pub key: PingValidationKey,
    pub dest: Destination,
    pub on_complete: Option<PingCompletionCallback>,
}

/////////////////////////////////////
// Processor State (internal, not shared)

struct PingCompletionResult {
    group: PingValidationGroup,
    key: PingValidationKey,
    result: Result<NetworkResult<Answer<StatusResult>>, RPCError>,
    on_complete: Option<PingCompletionCallback>,
}

#[derive(Default)]
struct PingValidationProcessorState {
    /// Per-group queued items, sorted by priority (BTreeMap key = priority number, 0 = highest)
    groups: BTreeMap<PingValidationGroup, BTreeMap<usize, VecDeque<PingValidationEntry>>>,
    /// Per-group in-flight counts
    group_in_flight: BTreeMap<PingValidationGroup, usize>,
    /// Keys currently queued (for deduplication)
    queued_keys: HashSet<PingValidationKey>,
    /// Keys currently in-flight (for deduplication)
    in_process_keys: HashSet<PingValidationKey>,
}

impl PingValidationProcessorState {
    fn new() -> Self {
        Self::default()
    }

    /// Add an entry to the priority queue, deduplicating against queued and in-process keys
    fn enqueue(&mut self, entry: PingValidationEntry) -> bool {
        if self.in_process_keys.contains(&entry.key) || self.queued_keys.contains(&entry.key) {
            return false;
        }
        self.queued_keys.insert(entry.key.clone());
        self.groups
            .entry(entry.group)
            .or_default()
            .entry(entry.priority)
            .or_default()
            .push_back(entry);
        true
    }

    /// Start as much pending work as possible, respecting per-group parallelism limits
    fn start_pending_work(
        &mut self,
        registry: &VeilidComponentRegistry,
        in_flight: &mut FuturesUnordered<PinBoxFutureStatic<PingCompletionResult>>,
    ) {
        // Iterate groups in order (RouteTest=0 first, then Keepalive=1, then Reliability=2)
        let groups: Vec<PingValidationGroup> = self.groups.keys().copied().collect();
        for group in groups {
            let max_parallel = group.max_parallel();
            let current_in_flight = *self.group_in_flight.entry(group).or_insert(0);
            let available = max_parallel.saturating_sub(current_in_flight);
            if available == 0 {
                continue;
            }

            let Some(priority_map) = self.groups.get_mut(&group) else {
                continue;
            };

            let mut started = 0usize;
            // Take items from lowest priority number first (BTreeMap iterates in ascending order)
            let priorities: Vec<usize> = priority_map.keys().copied().collect();
            for priority in priorities {
                if started >= available {
                    break;
                }
                let Some(queue) = priority_map.get_mut(&priority) else {
                    continue;
                };
                while started < available {
                    let Some(entry) = queue.pop_front() else {
                        break;
                    };
                    self.queued_keys.remove(&entry.key);
                    self.in_process_keys.insert(entry.key.clone());

                    let fut_group = entry.group;
                    let fut_key = entry.key.clone();
                    let fut_dest = entry.dest.clone();
                    let fut_on_complete = entry.on_complete;
                    let fut_registry = registry.clone();

                    in_flight.push(Box::pin(async move {
                        #[cfg(feature = "verbose-tracing")]
                        veilid_log!(fut_registry debug "--> validator ping ({:?}) to {:?}", fut_group, fut_dest);

                        let rpc_processor = fut_registry.rpc_processor();
                        let result =
                            Box::pin(rpc_processor.rpc_call_status(fut_dest)).await;

                        PingCompletionResult {
                            group: fut_group,
                            key: fut_key,
                            result,
                            on_complete: fut_on_complete,
                        }
                    }));

                    started += 1;
                }
                // Clean up empty queues
                if queue.is_empty() {
                    priority_map.remove(&priority);
                }
            }

            // Clean up empty priority maps
            if priority_map.is_empty() {
                self.groups.remove(&group);
            }

            *self.group_in_flight.entry(group).or_insert(0) += started;
        }
    }

    /// Handle a completed ping: update tracking, invoke callback, re-enqueue follow-ups
    fn handle_completion(
        &mut self,
        result: PingCompletionResult,
        registry: &VeilidComponentRegistry,
    ) {
        // Update tracking
        self.in_process_keys.remove(&result.key);
        if let Some(count) = self.group_in_flight.get_mut(&result.group) {
            *count = count.saturating_sub(1);
        }

        // Invoke callback and enqueue follow-up entries
        if let Some(callback) = result.on_complete {
            let follow_ups = callback(registry.clone(), result.result);
            for entry in follow_ups {
                self.enqueue(entry);
            }
        }
    }

    /// Returns the total number of queued items
    fn queued_count(&self) -> usize {
        self.groups
            .values()
            .flat_map(|pm| pm.values())
            .map(|q| q.len())
            .sum()
    }

    /// Returns the total number of in-flight items
    fn in_flight_count(&self) -> usize {
        self.group_in_flight.values().sum()
    }
}

/////////////////////////////////////
// Background Processor

impl RoutingTable {
    /// Long-lived background processor for the ping validation queue.
    /// Spawned at startup, processes items immediately as they are enqueued.
    pub(crate) async fn ping_validation_processor(
        registry: VeilidComponentRegistry,
        stop_token: StopToken,
        rx: flume::Receiver<Vec<PingValidationEntry>>,
    ) {
        let mut state = PingValidationProcessorState::new();
        let mut in_flight = FuturesUnordered::<PinBoxFutureStatic<PingCompletionResult>>::new();

        loop {
            // Start as much pending work as possible from the priority queue
            state.start_pending_work(&registry, &mut in_flight);

            if in_flight.is_empty() {
                // Nothing in-flight: block on channel recv
                match rx.recv_async().timeout_at(stop_token.clone()).await {
                    Ok(Ok(entries)) => {
                        for entry in entries {
                            state.enqueue(entry);
                        }
                    }
                    _ => break, // channel closed or stop token
                }
            } else {
                // Stuff in-flight: race channel recv vs future completion,
                // but also respect the stop token so shutdown isn't blocked
                // waiting for in-flight RPC timeouts.
                let recv_fut = rx.recv_async();
                let next_fut = in_flight.next();

                match select(recv_fut, next_fut)
                    .timeout_at(stop_token.clone())
                    .await
                {
                    Ok(Either::Left((Ok(entries), _))) => {
                        // New entries received from channel
                        for entry in entries {
                            state.enqueue(entry);
                        }
                    }
                    Ok(Either::Left((Err(_), _))) => {
                        // Channel closed, abandon in-flight items
                        break;
                    }
                    Ok(Either::Right((Some(result), _))) => {
                        // A ping completed
                        state.handle_completion(result, &registry);
                    }
                    Ok(Either::Right((None, _))) => {
                        // FuturesUnordered empty (shouldn't happen since we checked)
                        continue;
                    }
                    Err(_) => {
                        // Stop token fired, shut down immediately
                        break;
                    }
                }
            }
        }

        veilid_log!(registry debug "Ping validation processor stopped. {} queued, {} in-flight remaining.",
            state.queued_count(), state.in_flight_count());
    }

    /////////////////////////////////////
    // Enqueue APIs

    /// Enqueue ping validation entries with full control (callbacks, groups, priorities)
    pub fn enqueue_ping_validation_entries(&self, entries: Vec<PingValidationEntry>) {
        if entries.is_empty() {
            return;
        }
        if let Err(e) = self.ping_validation_sender.lock().send(entries) {
            veilid_log!(self warn "Failed to enqueue ping validations: channel closed ({} entries dropped)", e.into_inner().len());
        }
    }

    /// Convenience wrapper for simple destination pings (Destination key, no callback)
    pub fn enqueue_ping_validations(
        &self,
        purpose: String,
        group: PingValidationGroup,
        priority: usize,
        ping_validations: Vec<Destination>,
    ) {
        if ping_validations.is_empty() {
            return;
        }
        let entries: Vec<PingValidationEntry> = ping_validations
            .into_iter()
            .map(|dest| PingValidationEntry {
                group,
                priority,
                key: PingValidationKey::Destination(dest.clone()),
                dest,
                on_complete: None,
            })
            .collect();
        let count = entries.len();
        veilid_log!(self debug "[{}]: Enqueuing {} pings (group={:?}, priority={})", purpose, count, group, priority);
        self.enqueue_ping_validation_entries(entries);
    }

    /////////////////////////////////////
    // Reliability Ping Validations

    /// Ping each node in the routing table if they need to be pinged to determine their reliability
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip(self), err))]
    pub fn add_reliability_ping_validations(
        &self,
        cur_ts: Timestamp,
        routing_domain: RoutingDomain,
    ) -> EyreResult<()> {
        let priority_nodes = self.get_relability_ping_nodes(routing_domain, cur_ts);

        let name = format!("Reliability({})", routing_domain);
        for (priority, node_refs) in priority_nodes {
            let mut validations = vec![];
            for nr in node_refs {
                let nr = nr.with_sequencing(Sequencing::PreferOrdered);
                validations.push(Destination::direct(nr, None));
            }
            self.enqueue_ping_validations(
                name.clone(),
                PingValidationGroup::Reliability,
                priority,
                validations,
            );
        }

        Ok(())
    }

    /////////////////////////////////////
    // Route Test Integration

    /// Enqueue route test pings for a set of routes.
    /// Builds loopback destinations and creates callback chains for multi-ping testing.
    pub async fn enqueue_route_tests(&self, route_ids: Vec<RouteId>, priority: usize) {
        let rss = self.route_spec_store();

        let mut entries = Vec::new();
        for route_id in route_ids {
            let is_remote = rss.is_route_id_remote(&route_id);

            if is_remote {
                // Remote route: single ping, simpler setup
                match Self::build_remote_route_test_entry(rss, &route_id, priority) {
                    Some(entry) => entries.push(entry),
                    None => {
                        veilid_log!(self debug "Could not build remote route test for {}", route_id);
                    }
                }
            } else {
                // Allocated route: multi-ping with callback chain
                match Self::build_allocated_route_test_entry(rss, &route_id, priority).await {
                    Some(entry) => entries.push(entry),
                    None => {
                        veilid_log!(self debug "Could not build allocated route test for {}", route_id);
                    }
                }
            }
        }

        if !entries.is_empty() {
            self.enqueue_ping_validation_entries(entries);
        }
    }

    /// Build a PingValidationEntry for testing an allocated (local) route
    async fn build_allocated_route_test_entry(
        rss: &RouteSpecStore,
        route_id: &RouteId,
        priority: usize,
    ) -> Option<PingValidationEntry> {
        // Get the best route key and hop refs
        let (key, hops) = match rss.get_route_test_info(route_id) {
            Some(v) => v,
            None => {
                // Route doesn't exist or has no best key
                return None;
            }
        };

        // Assemble the private route
        let private_route = match rss.assemble_single_private_route(&key, None).await {
            Ok(v) => v,
            Err(VeilidAPIError::InvalidTarget { message: _ }) => {
                // Route missing means it's dead
                veilid_log!(rss debug "Route {} is dead (invalid target), releasing", route_id);
                rss.release_route(route_id.clone());
                return None;
            }
            Err(VeilidAPIError::TryAgain { message: _ }) => {
                // Can't assemble right now, skip
                return None;
            }
            Err(e) => {
                veilid_log!(rss debug "Error assembling route {}: {}", route_id, e);
                return None;
            }
        };

        // Build the loopback destination
        let hop_count = hops.len();
        let safety_spec = SafetySpec {
            preferred_route: Some(route_id.clone()),
            hop_count,
            stability: Stability::Reliable,
            sequencing: Sequencing::PreferOrdered,
        };
        let safety_selection = SafetySelection::Safe(safety_spec);
        let dest = Destination::PrivateRoute {
            private_route,
            safety_selection,
        };

        let route_id_clone = route_id.clone();
        let dest_clone = dest.clone();

        Some(PingValidationEntry {
            group: PingValidationGroup::RouteTest,
            priority,
            key: PingValidationKey::RouteTest {
                route_id: route_id.clone(),
                ping_index: 0,
            },
            dest,
            on_complete: Some(Self::make_route_test_callback(
                route_id_clone,
                dest_clone,
                hops,
                0,
                ROUTE_TEST_PING_COUNT,
            )),
        })
    }

    /// Build a PingValidationEntry for testing a remote route
    fn build_remote_route_test_entry(
        rss: &RouteSpecStore,
        route_id: &RouteId,
        priority: usize,
    ) -> Option<PingValidationEntry> {
        let private_route = rss.best_remote_private_route(route_id)?;

        let safety_spec = SafetySpec {
            preferred_route: None,
            hop_count: rss.get_default_route_hop_count_safe(),
            stability: Stability::Reliable,
            sequencing: Sequencing::PreferOrdered,
        };
        let safety_selection = SafetySelection::Safe(safety_spec);
        let dest = Destination::PrivateRoute {
            private_route,
            safety_selection,
        };

        let route_id_clone = route_id.clone();

        // Remote routes: single ping, callback just handles success/failure
        Some(PingValidationEntry {
            group: PingValidationGroup::RouteTest,
            priority,
            key: PingValidationKey::RouteTest {
                route_id: route_id.clone(),
                ping_index: 0,
            },
            dest,
            on_complete: Some(Box::new(
                move |registry: VeilidComponentRegistry,
                      result: Result<NetworkResult<Answer<StatusResult>>, RPCError>|
                      -> Vec<PingValidationEntry> {
                    match result {
                        Ok(NetworkResult::Value(_)) => {
                            // Success - route is alive
                            veilid_log!(registry trace "Remote route test PASSED: {}", route_id_clone);
                        }
                        Ok(_) => {
                            // Network result but not a value - route failed
                            veilid_log!(registry debug "Remote route test failed (no response): {}", route_id_clone);
                            let routing_table = registry.routing_table();
                            let rss = routing_table.route_spec_store();
                            rss.release_route(route_id_clone);
                        }
                        Err(e) => {
                            veilid_log!(registry debug "Remote route test error: {} - {}", route_id_clone, e);
                        }
                    }
                    Vec::new()
                },
            )),
        })
    }

    /// Create a callback for the route test chain.
    /// On success with more pings needed: returns next entry in the chain.
    /// On failure: reports failed route test on hop nodes, releases route.
    /// On final success: returns empty (RPC processor already set last_known_valid_ts).
    fn make_route_test_callback(
        route_id: RouteId,
        dest: Destination,
        hops: Vec<NodeRef>,
        ping_index: usize,
        total_pings: usize,
    ) -> PingCompletionCallback {
        Box::new(
            move |registry: VeilidComponentRegistry,
                  result: Result<NetworkResult<Answer<StatusResult>>, RPCError>|
                  -> Vec<PingValidationEntry> {
                match result {
                    Ok(NetworkResult::Value(_)) => {
                        // Ping succeeded
                        let next_index = ping_index + 1;
                        veilid_log!(registry trace "Route test ping {}/{} succeeded: {}", ping_index + 1, total_pings, route_id);
                        if next_index < total_pings {
                            // More pings needed - return next entry in chain
                            vec![PingValidationEntry {
                                group: PingValidationGroup::RouteTest,
                                priority: 0, // Keep highest priority for chain continuation
                                key: PingValidationKey::RouteTest {
                                    route_id: route_id.clone(),
                                    ping_index: next_index,
                                },
                                dest: dest.clone(),
                                on_complete: Some(Self::make_route_test_callback(
                                    route_id,
                                    dest,
                                    hops,
                                    next_index,
                                    total_pings,
                                )),
                            }]
                        } else {
                            // All pings passed - route is verified
                            // Note: last_known_valid_ts is already set by record_answer_received
                            // in the RPC processor on the first successful response
                            veilid_log!(registry trace "Route test PASSED ({} pings): {}", total_pings, route_id);
                            Vec::new()
                        }
                    }
                    Ok(_) => {
                        // Network result but not a value - route failed
                        veilid_log!(registry debug "Route test failed at ping {}/{}: {} (no response)",
                            ping_index + 1, total_pings, route_id);

                        // Report failed route test on hop nodes
                        for hop in &hops {
                            hop.report_failed_route_test();
                        }

                        // Release the dead route
                        let routing_table = registry.routing_table();
                        let rss = routing_table.route_spec_store();
                        rss.release_route(route_id);

                        Vec::new()
                    }
                    Err(e) => {
                        veilid_log!(registry debug "Route test error at ping {}/{}: {} - {}",
                            ping_index + 1, total_pings, route_id, e);
                        // Don't release on RPC error (could be transient)
                        Vec::new()
                    }
                }
            },
        )
    }
}
