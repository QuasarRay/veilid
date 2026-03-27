use super::*;
use crate::rpc_processor::Destination;

#[must_use]
pub enum RouteStatsDisposition {
    /// Route is still valid
    Valid,
    /// Route is locked
    Locked,
    /// Route is invalid because it has failed to send too many times
    InvalidSendFailure,
    /// Route is invalid because it has lost too many answers
    InvalidLostAnswers,
}

#[derive(Clone, Debug, Default)]
pub struct RouteStats {
    /// Lock count: when > 0, route is locked from invalidation and testing
    pub lock_count: usize,
    /// Consecutive failed to send count
    pub failed_to_send: usize,
    /// Per-destination lost answer tracking: maps destination public key to lost answer count
    pub lost_answer_destinations: HashMap<PublicKey, usize>,
    /// Timestamp of when the route was created
    pub created_ts: Timestamp,
    /// Timestamp of when the route was last checked for validity or received traffic
    pub last_known_valid_ts: Option<Timestamp>,
    /// Timestamp of when the route was last sent to
    pub last_sent_ts: Option<Timestamp>,
    /// Timestamp of when the route last received a question or statement
    pub last_rcvd_question_ts: Option<Timestamp>,
    /// Timestamp of when the route last received an answer
    pub last_rcvd_answer_ts: Option<Timestamp>,
    /// Transfers up and down
    pub transfer: TransferStatsDownUp,
    /// Latency stats
    pub latency: LatencyStats,
    /// Answer stats
    pub answer: AnswerStats,
    /// Accounting mechanism for this route's RPC latency
    latency_stats_accounting: LatencyStatsAccounting,
    /// Accounting mechanism for the bandwidth across this route
    transfer_stats_accounting: TransferStatsAccounting,
    /// Accounting mechanism for this route's RPC answers
    answer_stats_accounting: AnswerStatsAccounting,
}

impl fmt::Display for RouteStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "lock_count: {}", self.lock_count)?;
        writeln!(f, "created: {}", self.created_ts)?;
        writeln!(
            f,
            "# lost-answer-dests/failed-to-send: {} / {}",
            self.lost_answer_destinations.len(),
            self.failed_to_send
        )?;
        writeln!(
            f,
            "last_known_valid:   {}",
            f.to_string_opt(self.last_known_valid_ts)
        )?;
        writeln!(
            f,
            "last_sent:          {}",
            f.to_string_opt(self.last_sent_ts)
        )?;
        writeln!(
            f,
            "last_rcvd_question: {}",
            f.to_string_opt(self.last_rcvd_question_ts)
        )?;
        writeln!(
            f,
            "last_rcvd_answer:   {}",
            f.to_string_opt(self.last_rcvd_answer_ts)
        )?;
        writeln!(f, "transfer:           {}", f.to_string(&self.transfer))?;
        writeln!(f, "latency:            {}", f.to_string(&self.latency))?;
        writeln!(f, "answer:             {}", f.to_string(&self.answer))?;

        Ok(())
    }
}

impl RouteStats {
    /// Make new route stats
    pub fn new(created_ts: Timestamp) -> Self {
        Self {
            created_ts,
            ..Default::default()
        }
    }

    /// Make new route stats from a route set spec detail stats
    pub fn new_from_spec_detail_stats(stats: RouteSetSpecDetailStats) -> Self {
        Self {
            created_ts: stats.created_ts,
            transfer: stats.transfer,
            latency: stats.latency,
            answer: stats.answer,
            ..Default::default()
        }
    }

    /// Get the disposition of this route
    pub fn disposition(&self) -> RouteStatsDisposition {
        if self.lock_count > 0 {
            return RouteStatsDisposition::Locked;
        }
        if self.failed_to_send >= ROUTE_SEND_FAILURES_INVALIDATE_THRESHOLD {
            RouteStatsDisposition::InvalidSendFailure
        } else if self.lost_answer_destinations.len()
            >= ROUTE_LOST_DESTINATIONS_INVALIDATE_THRESHOLD
        {
            RouteStatsDisposition::InvalidLostAnswers
        } else {
            RouteStatsDisposition::Valid
        }
    }

    /// Mark a route as having failed to send
    pub fn record_send_failed(&mut self) {
        self.failed_to_send += 1;
    }

    /// Mark a route as having lost an answer for a specific destination
    pub fn record_lost_answer(&mut self, destination: &Destination) {
        let cur_ts = Timestamp::now();
        self.answer_stats_accounting.record_lost_answer(cur_ts);

        let Ok(dest_key) = destination.destination_key() else {
            return;
        };
        *self.lost_answer_destinations.entry(dest_key).or_insert(0) += 1;
    }

    /// Mark a route as having received a question or statement
    pub fn record_question_received(&mut self, cur_ts: Timestamp, bytes: ByteCount) {
        self.last_rcvd_question_ts = Some(cur_ts);
        self.last_known_valid_ts = Some(cur_ts);
        self.transfer_stats_accounting.add_down(bytes);
        self.answer_stats_accounting.record_question(cur_ts);
    }

    /// Mark a route as having received an answer from a specific destination
    pub fn record_answer_received(
        &mut self,
        cur_ts: Timestamp,
        bytes: ByteCount,
        _destination: &Destination,
    ) {
        self.last_rcvd_answer_ts = Some(cur_ts);
        self.last_known_valid_ts = Some(cur_ts);
        self.transfer_stats_accounting.add_down(bytes);
        self.answer_stats_accounting.record_answer(cur_ts);

        // Receiving any answer from any destination means the route is functional
        self.lost_answer_destinations.clear();
    }

    /// Mark a route as having been sent to
    pub fn record_sent(&mut self, cur_ts: Timestamp, bytes: ByteCount) {
        self.last_sent_ts = Some(cur_ts);
        self.transfer_stats_accounting.add_up(bytes);

        // If we sent successfully, then reset 'failed_to_send'
        self.failed_to_send = 0;
    }

    /// Mark a route as having been sent to
    pub fn record_latency(&mut self, latency: TimestampDuration) {
        self.latency = self.latency_stats_accounting.record_latency(latency);
    }

    /// Roll transfers for these route stats
    pub fn roll_transfers(&mut self, last_ts: Timestamp, cur_ts: Timestamp) {
        self.transfer_stats_accounting
            .roll_transfers(last_ts, cur_ts, &mut self.transfer);
    }
    pub fn roll_answers(&mut self, cur_ts: Timestamp) {
        self.answer = self.answer_stats_accounting.roll_answers(cur_ts);
    }

    /// Get the latency stats
    pub fn latency_stats(&self) -> &LatencyStats {
        &self.latency
    }

    /// Get the transfer stats
    pub fn transfer_stats(&self) -> &TransferStatsDownUp {
        &self.transfer
    }

    /// Reset stats when network restarts
    pub fn reset(&mut self) {
        self.last_known_valid_ts = None;
        self.last_sent_ts = None;
        self.last_rcvd_question_ts = None;
        self.last_rcvd_answer_ts = None;
        self.failed_to_send = 0;
        self.lost_answer_destinations.clear();
    }

    /// Check if a route needs testing
    pub fn needs_testing(&self, cur_ts: Timestamp) -> bool {
        // If the route is locked, testing should wait
        if self.lock_count > 0 {
            return false;
        }
        // Has the route had any failures lately?
        if !self.lost_answer_destinations.is_empty() || self.failed_to_send > 0 {
            // If so, always test
            return true;
        }

        // Has the route been tested within the idle time we'd want to check things?
        // (also if we've received successfully over the route, this will get set)
        if let Some(last_tested_ts) = self.last_known_valid_ts {
            if cur_ts.duration_since(last_tested_ts)
                > TimestampDuration::new_ms(ROUTE_MIN_IDLE_TIME_MS as u64)
            {
                return true;
            }
        } else {
            // If this route has never been tested, it needs to be
            return true;
        }

        false
    }
}

impl RouteSpecStore {
    /// Modify the route statistics for allocated routes
    /// Changes made to the route stats may invalidate the route in the compiled route cache
    /// or lead to the route being tested and eventually removal.
    pub fn update_allocated_route_stats<F>(&self, cur_ts: Timestamp, key: &PublicKey, f: F)
    where
        F: FnOnce(&mut RouteStats) -> VeilidAPIResult<()>,
    {
        // Check for stub route (ignore changes to stubs)
        if self.routing_table().public_keys().contains(key) {
            return;
        }

        let cache = self.cache.read();
        if let Err(e) = cache.update_allocated_route_stats(cur_ts, key, f) {
            veilid_log!(self error "Error updating route stats for allocated route {}: {}", key, e);
        }
    }

    /// Modify the route statistics for remote routes
    /// Changes made to the route stats may invalidate the route in the compiled route cache
    pub fn update_remote_route_stats<F>(&self, cur_ts: Timestamp, key: &PublicKey, f: F)
    where
        F: FnOnce(&mut RouteStats) -> VeilidAPIResult<()>,
    {
        // Check for stub route (ignore changes to stubs)
        if self.routing_table().public_keys().contains(key) {
            return;
        }

        let cache = self.cache.read();
        if let Err(e) = cache.update_remote_route_stats(cur_ts, key, f) {
            veilid_log!(self error "Error updating route stats for remote route {}: {}", key, e);
        }
    }

    /// Process transfer statistics to get averages
    pub fn roll_transfers(&self, last_ts: Timestamp, cur_ts: Timestamp) {
        // Careful with locking order here, we need to lock the content before the cache
        let content = self.content.read();
        let cache = self.cache.read();

        // Roll transfers for allocated route cache and remote private routes
        cache.roll_transfers(last_ts, cur_ts);

        // Update transfers from cache into content to save them
        content.update_transfers(&cache);

        // Also update latency here because we don't use this in realtime from the content like we do from the cache
        content.update_latency(&cache);
    }

    /// Process answer statistics
    pub fn roll_answers(&self, cur_ts: Timestamp) {
        // Careful with locking order here, we need to lock the content before the cache
        let content = self.content.read();
        let cache = self.cache.read();

        // Roll transfers for the cache
        cache.roll_answers(cur_ts);

        // Update answers from cache into content to save them
        content.update_answers(&cache);
    }
}
