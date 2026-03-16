use super::*;
use crate::rpc_processor::Destination;

#[must_use]
pub enum RouteStatsDisposition {
    /// Route is still valid
    Valid,
    /// Route is invalid because it has failed to send too many times
    InvalidSendFailure,
    /// Route is invalid because it has lost too many answers
    InvalidLostAnswers,
}

impl RouteStatsDisposition {
    pub fn is_valid(&self) -> bool {
        matches!(self, RouteStatsDisposition::Valid)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteStats {
    /// Consecutive failed to send count
    #[serde(skip)]
    pub failed_to_send: u32,
    /// Per-destination lost answer tracking: maps destination public key to lost answer count
    #[serde(skip)]
    pub lost_answer_destinations: HashMap<PublicKey, u32>,
    /// Timestamp of when the route was created
    pub created_ts: Timestamp,
    /// Timestamp of when the route was last checked for validity or received traffic
    #[serde(skip)]
    pub last_known_valid_ts: Option<Timestamp>,
    /// Timestamp of when the route was last sent to
    #[serde(skip)]
    pub last_sent_ts: Option<Timestamp>,
    /// Timestamp of when the route last received a question or statement
    #[serde(skip)]
    pub last_rcvd_question_ts: Option<Timestamp>,
    /// Timestamp of when the route last received an answer
    #[serde(skip)]
    pub last_rcvd_answer_ts: Option<Timestamp>,
    /// Transfers up and down
    pub transfer: TransferStatsDownUp,
    /// Latency stats
    pub latency: LatencyStats,
    /// Answer stats
    pub answer: AnswerStats,
    /// Accounting mechanism for this route's RPC latency
    #[serde(skip)]
    latency_stats_accounting: LatencyStatsAccounting,
    /// Accounting mechanism for the bandwidth across this route
    #[serde(skip)]
    transfer_stats_accounting: TransferStatsAccounting,
    /// Accounting mechanism for this route's RPC answers
    #[serde(skip)]
    answer_stats_accounting: AnswerStatsAccounting,
}

impl fmt::Display for RouteStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            if let Some(ts) = &self.last_known_valid_ts {
                ts.to_string()
            } else {
                "None".to_owned()
            }
        )?;
        writeln!(
            f,
            "last_sent:          {}",
            if let Some(ts) = &self.last_sent_ts {
                ts.to_string()
            } else {
                "None".to_owned()
            }
        )?;
        writeln!(
            f,
            "last_rcvd_question: {}",
            if let Some(ts) = &self.last_rcvd_question_ts {
                ts.to_string()
            } else {
                "None".to_owned()
            }
        )?;
        write!(f, "transfer:\n{}", indent_all_string(&self.transfer))?;
        write!(f, "latency: {}", self.latency)?;
        write!(f, "answer:\n{}", indent_all_string(&self.answer))?;

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
    /// Mark a route as having failed to send
    pub fn record_send_failed(&mut self) -> RouteStatsDisposition {
        self.failed_to_send += 1;
        if self.failed_to_send >= ROUTE_SEND_FAILURES_INVALIDATE_THRESHOLD {
            RouteStatsDisposition::InvalidSendFailure
        } else {
            RouteStatsDisposition::Valid
        }
    }

    /// Mark a route as having lost an answer for a specific destination
    pub fn record_lost_answer(&mut self, destination: &Destination) -> RouteStatsDisposition {
        let cur_ts = Timestamp::now();
        self.answer_stats_accounting.record_lost_answer(cur_ts);

        let Ok(dest_key) = destination.destination_key() else {
            return RouteStatsDisposition::Valid;
        };
        *self.lost_answer_destinations.entry(dest_key).or_insert(0) += 1;
        if self.lost_answer_destinations.len() as u32
            >= ROUTE_LOST_DESTINATIONS_INVALIDATE_THRESHOLD
        {
            RouteStatsDisposition::InvalidLostAnswers
        } else {
            RouteStatsDisposition::Valid
        }
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
        destination: &Destination,
    ) {
        self.last_rcvd_answer_ts = Some(cur_ts);
        self.last_known_valid_ts = Some(cur_ts);
        if let Ok(dest_key) = destination.destination_key() {
            self.lost_answer_destinations.remove(&dest_key);
        }
        self.transfer_stats_accounting.add_down(bytes);
        self.answer_stats_accounting.record_answer(cur_ts);
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
    /// Get the route statistics for any route we know about, allocated or remote
    pub fn with_route_stats_mut<F, R>(&self, cur_ts: Timestamp, key: &PublicKey, f: F) -> Option<R>
    where
        F: FnOnce(&mut RouteStats) -> R,
    {
        let inner = self.inner.read();

        // Check for stub route
        if self.routing_table().public_keys().contains(key) {
            return None;
        }

        // Check for allocated route
        if let Some(rsid) = inner.content.get_id_by_key(key) {
            if let Some(rsd) = inner.content.get_detail(&rsid) {
                return Some(rsd.with_stats_mut(f));
            }
        }

        // Check for remote route
        if let Some(rrid) = inner.cache.get_remote_private_route_id_by_key(key) {
            if let Some(rpri) = inner.cache.peek_remote_private_route(cur_ts, &rrid) {
                return Some(rpri.with_stats_mut(f));
            }
        }

        None
    }

    /// Lock an allocated route from invalidation by its public key
    pub fn lock_route(&self, key: &PublicKey) {
        let inner = self.inner.read();
        if let Some(rsid) = inner.content.get_id_by_key(key) {
            if let Some(rsd) = inner.content.get_detail(&rsid) {
                rsd.lock();
            }
        }
    }

    /// Unlock an allocated route and check if it should be invalidated now
    pub fn unlock_route_and_check(&self, key: &PublicKey) {
        let should_invalidate = {
            let inner = self.inner.read();
            let Some(rsid) = inner.content.get_id_by_key(key) else {
                return;
            };
            let Some(rsd) = inner.content.get_detail(&rsid) else {
                return;
            };
            rsd.unlock();
            // Check if accumulated failures now warrant invalidation
            !rsd.is_locked()
                && rsd.with_stats(|s| {
                    s.failed_to_send >= ROUTE_SEND_FAILURES_INVALIDATE_THRESHOLD
                        || s.lost_answer_destinations.len() as u32
                            >= ROUTE_LOST_DESTINATIONS_INVALIDATE_THRESHOLD
                })
        };
        if should_invalidate {
            self.invalidate_compiled_route_cache(key);
        }
    }

    /// Check if an allocated route is locked from invalidation
    pub fn is_route_locked(&self, key: &PublicKey) -> bool {
        let inner = self.inner.read();
        if let Some(rsid) = inner.content.get_id_by_key(key) {
            if let Some(rsd) = inner.content.get_detail(&rsid) {
                return rsd.is_locked();
            }
        }
        false
    }

    /// Process transfer statistics to get averages
    pub fn roll_transfers(&self, last_ts: Timestamp, cur_ts: Timestamp) {
        let inner = self.inner.read();

        // Roll transfers for allocated routes
        inner.content.roll_transfers(last_ts, cur_ts);

        // Roll transfers for remote private routes
        inner.cache.roll_transfers(last_ts, cur_ts);
    }

    /// Process answer statistics
    pub fn roll_answers(&self, cur_ts: Timestamp) {
        let inner = self.inner.read();

        // Roll transfers for allocated routes
        inner.content.roll_answers(cur_ts);

        // Roll transfers for remote private routes
        inner.cache.roll_answers(cur_ts);
    }
}
