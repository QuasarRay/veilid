use super::*;

/// Measurement of communications latency to this node over all RPC questions
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), derive(Tsify))]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
pub struct LatencyStats {
    /// fastest latency in the ROLLING_LATENCIES_SIZE last latencies
    pub fastest: TimestampDuration,
    /// average latency over the ROLLING_LATENCIES_SIZE last latencies
    pub average: TimestampDuration,
    /// slowest latency in the ROLLING_LATENCIES_SIZE last latencies
    pub slowest: TimestampDuration,
    /// trimmed mean with lowest 90% latency in the ROLLING_LATENCIES_SIZE
    #[serde(default)]
    pub tm90: TimestampDuration,
    /// trimmed mean with lowest 75% latency in the ROLLING_LATENCIES_SIZE
    #[serde(default)]
    pub tm75: TimestampDuration,
    /// p90 latency in the ROLLING_LATENCIES_SIZE
    #[serde(default)]
    pub p90: TimestampDuration,
    /// p75 latency in the ROLLING_LATENCIES_SIZE
    #[serde(default)]
    pub p75: TimestampDuration,
}

impl fmt::Display for LatencyStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} slow | {} avg | {} fast | {} tm90 | {} tm75 | {} p90 | {} p75",
            f.to_string(self.slowest),
            f.to_string(self.average),
            f.to_string(self.fastest),
            f.to_string(self.tm90),
            f.to_string(self.tm75),
            f.to_string(self.p90),
            f.to_string(self.p75)
        )?;
        Ok(())
    }
}

/// Measurement of how much data has transferred to or from this node over a time span
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), derive(Tsify))]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
pub struct TransferStats {
    /// total amount transferred ever
    pub total: ByteCount,
    /// maximum rate over the ROLLING_TRANSFERS_SIZE last amounts
    pub maximum: ByteCount,
    /// average rate over the ROLLING_TRANSFERS_SIZE last amounts
    pub average: ByteCount,
    /// minimum rate over the ROLLING_TRANSFERS_SIZE last amounts
    pub minimum: ByteCount,
}

impl fmt::Display for TransferStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/s min | {}/s avg | {}/s max | {} total",
            f.to_string(self.minimum),
            f.to_string(self.average),
            f.to_string(self.maximum),
            if f.alternate() {
                format!(
                    "{} ({} bytes)",
                    human_byte_count(self.total.as_u64()),
                    self.total.as_u64()
                )
            } else {
                format!("{}", self.total.as_u64())
            },
        )?;
        Ok(())
    }
}

/// Transfer statistics from a node to our own (down) and
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), derive(Tsify))]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
pub struct TransferStatsDownUp {
    pub down: TransferStats,
    pub up: TransferStats,
}

impl fmt::Display for TransferStatsDownUp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Down: {}\nUp:   {}",
            f.to_string(&self.down),
            f.to_string(&self.up)
        )
    }
}

/// Measurement of what states the node has been in over a time span
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), derive(Tsify))]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
pub struct StateStats {
    /// total amount of time measured
    pub span: TimestampDuration,
    /// amount of time spent in a reliable state
    pub reliable: TimestampDuration,
    /// amount of time spent in an unreliable state
    pub unreliable: TimestampDuration,
    /// amount of time spent in a dead state
    pub dead: TimestampDuration,
    /// amount of time spent in a punished state
    pub punished: TimestampDuration,
    /// state reason stats for this peer
    #[serde(default)]
    pub reason: StateReasonStats,
}

impl fmt::Display for StateStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "span:       {}", f.to_string(self.span))?;
        writeln!(f, "reliable:   {}", f.to_string(self.reliable))?;
        writeln!(f, "unreliable: {}", f.to_string(self.unreliable))?;
        writeln!(f, "dead:       {}", f.to_string(self.dead))?;
        writeln!(f, "punished:   {}", f.to_string(self.punished))?;
        write!(
            f,
            "reason:\n{}",
            indent_all_string(f.to_string(&self.reason))
        )?;
        Ok(())
    }
}

/// Measurement of what state reasons the node has been in over a time span
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), derive(Tsify))]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
pub struct StateReasonStats {
    /// time spent dead due to being unable to send
    pub can_not_send: TimestampDuration,
    /// time spent dead because of too many lost answers
    pub too_many_lost_answers: TimestampDuration,
    /// time spent dead because of no ping response
    pub no_ping_response: TimestampDuration,
    /// time spent unreliable because of failures to send
    pub failed_to_send: TimestampDuration,
    /// time spent unreliable because of lost answers
    pub lost_answers: TimestampDuration,
    /// time spent unreliable because of not being seen consecutively
    pub not_seen_consecutively: TimestampDuration,
    /// time spent unreliable because we are in the unreliable ping span
    pub in_unreliable_ping_span: TimestampDuration,
}

impl fmt::Display for StateReasonStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "(dead) can_not_send:     {}",
            f.to_string(self.can_not_send)
        )?;
        writeln!(
            f,
            "(dead) lost_answers:     {}",
            f.to_string(self.too_many_lost_answers)
        )?;
        writeln!(
            f,
            "(dead) no_ping_response: {}",
            f.to_string(self.no_ping_response)
        )?;
        writeln!(
            f,
            "(urel) failed_to_send:   {}",
            f.to_string(self.failed_to_send)
        )?;
        writeln!(
            f,
            "(urel) lost_answers:     {}",
            f.to_string(self.lost_answers)
        )?;
        writeln!(
            f,
            "(urel) not_consecutive:  {}",
            f.to_string(self.not_seen_consecutively)
        )?;
        writeln!(
            f,
            "(urel) unreliable_ping:  {}",
            f.to_string(self.in_unreliable_ping_span)
        )?;
        writeln!(
            f,
            "(urel) can_not_send:     {}",
            f.to_string(self.can_not_send)
        )?;
        Ok(())
    }
}

/// Measurement of round-trip RPC question/answer performance
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), derive(Tsify))]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
pub struct AnswerStats {
    /// total amount of time measured
    pub span: TimestampDuration,
    /// number of questions sent in this span
    pub questions: u32,
    /// number of answers received in this span
    pub answers: u32,
    /// number of lost answers in this span
    pub lost_answers: u32,
    /// maximum number of received answers before a lost answer in this span
    pub consecutive_answers_maximum: u32,
    /// average number of received answers before a lost answer in this span
    pub consecutive_answers_average: u32,
    /// minimum number of received answers before a lost answer in this span
    pub consecutive_answers_minimum: u32,
    /// maximum number of timeouts before a received answer in this span
    pub consecutive_lost_answers_maximum: u32,
    /// average number of timeouts before a received answer in this span
    pub consecutive_lost_answers_average: u32,
    /// minimum number of timeouts before a received answer in this span
    pub consecutive_lost_answers_minimum: u32,
}

impl fmt::Display for AnswerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "span: {}", self.span)?;
        writeln!(
            f,
            "questions/answers/lost: {} / {} / {}",
            self.questions, self.answers, self.lost_answers
        )?;
        writeln!(
            f,
            "consecutive answers min/avg/max: {} / {} / {}",
            self.consecutive_answers_minimum,
            self.consecutive_answers_average,
            self.consecutive_answers_maximum
        )?;
        writeln!(
            f,
            "consecutive lost min/avg/max: {} / {} / {}",
            self.consecutive_lost_answers_minimum,
            self.consecutive_lost_answers_average,
            self.consecutive_lost_answers_maximum
        )?;

        Ok(())
    }
}

impl AnswerStats {
    /// Approximate aggregation for projecting per-transport stats into a
    /// coarser view: sum counts, max/min bounds, average the averages.
    pub fn merge(&mut self, other: &AnswerStats) {
        if self.questions == 0 && self.answers == 0 && self.lost_answers == 0 {
            *self = other.clone();
            return;
        }
        self.span = self.span.max(other.span);
        self.questions += other.questions;
        self.answers += other.answers;
        self.lost_answers += other.lost_answers;
        self.consecutive_answers_maximum = self
            .consecutive_answers_maximum
            .max(other.consecutive_answers_maximum);
        self.consecutive_answers_minimum = self
            .consecutive_answers_minimum
            .min(other.consecutive_answers_minimum);
        self.consecutive_answers_average =
            (self.consecutive_answers_average + other.consecutive_answers_average) / 2;
        self.consecutive_lost_answers_maximum = self
            .consecutive_lost_answers_maximum
            .max(other.consecutive_lost_answers_maximum);
        self.consecutive_lost_answers_minimum = self
            .consecutive_lost_answers_minimum
            .min(other.consecutive_lost_answers_minimum);
        self.consecutive_lost_answers_average =
            (self.consecutive_lost_answers_average + other.consecutive_lost_answers_average) / 2;
    }
}

/// Statistics for RPC operations performed on a node
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), derive(Tsify))]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
pub struct RPCStats {
    /// number of rpcs that have been sent in the total entry time range
    pub messages_sent: u32,
    /// number of rpcs that have been received in the total entry time range
    pub messages_rcvd: u32,
    /// number of questions issued that have yet to be answered
    pub questions_in_flight: u32,
    /// when the peer was last questioned (either successfully or not) and we wanted an answer
    pub last_question_ts: Option<Timestamp>,
    /// when the peer was last seen for any reason, including when we first attempted to reach out to it
    pub last_seen_ts: Option<Timestamp>,
    /// the timestamp of the first consecutive proof-of-life for this node (an answer or received question)
    pub first_consecutive_seen_ts: Option<Timestamp>,
    /// number of messages that have failed to send or connections dropped since we last successfully sent one
    pub failed_to_send: u32,
    /// number of attempts where no transport could be chosen (no routing domain, no peer info, no contact method)
    #[serde(default)]
    pub unreachable: u32,
}

impl fmt::Display for RPCStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "# sent/received/in-flight:      {} / {} / {}",
            self.messages_sent, self.messages_rcvd, self.questions_in_flight
        )?;
        writeln!(f, "# failed-to-send: {}", self.failed_to_send)?;
        writeln!(f, "# unreachable: {}", self.unreachable)?;
        writeln!(
            f,
            "last_question:      {}",
            f.to_string_opt(self.last_question_ts.as_ref())
        )?;
        writeln!(
            f,
            "last_seen:          {}",
            f.to_string_opt(self.last_seen_ts.as_ref())
        )?;
        writeln!(
            f,
            "first_consecutive:  {}",
            f.to_string_opt(self.first_consecutive_seen_ts.as_ref())
        )?;
        Ok(())
    }
}

/// Statistics for a peer in the routing table
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), derive(Tsify))]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
pub struct PeerStats {
    /// when the peer was added to the routing table
    pub time_added: Timestamp,
    #[serde(default)]
    /// information about RPCs
    pub rpc_stats: RPCStats,
    #[serde(default)]
    /// latency stats for this peer
    pub latency: Option<LatencyStats>,
    /// transfer stats for this peer
    #[serde(default)]
    pub transfer: TransferStatsDownUp,
    /// state stats for this peer
    #[serde(default)]
    pub state: StateStats,
    /// how long protected connections to this peer survived before being closed
    /// by the remote side; longer is better. None = no remote-closed protected
    /// drops yet observed.
    #[serde(default)]
    pub protected_connection_drop: Option<LatencyStats>,
}

impl fmt::Display for PeerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "time_added: {}", self.time_added)?;
        write!(
            f,
            "rpc_stats:\n{}",
            indent_all_string(f.to_string(&self.rpc_stats))
        )?;
        writeln!(f, "latency: {}", f.to_string_opt(self.latency.as_ref()))?;
        writeln!(
            f,
            "protected_connection_drop: {}",
            f.to_string_opt(self.protected_connection_drop.as_ref())
        )?;
        write!(
            f,
            "transfer:\n{}",
            indent_all_string(f.to_string(&self.transfer))
        )?;
        write!(f, "state:\n{}", indent_all_string(f.to_string(&self.state)))?;

        Ok(())
    }
}
