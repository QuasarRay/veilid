use super::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum BucketEntryTransportDeadReason {
    CanNotSend,
    TooManyLostAnswers,
    NoPingResponse,
}

impl fmt::Display for BucketEntryTransportDeadReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            match self {
                BucketEntryTransportDeadReason::CanNotSend => write!(f, "DFSEND"),
                BucketEntryTransportDeadReason::TooManyLostAnswers => write!(f, "DALOST"),
                BucketEntryTransportDeadReason::NoPingResponse => write!(f, "DNOPNG"),
            }
        } else {
            match self {
                BucketEntryTransportDeadReason::CanNotSend => write!(f, "Can not send"),
                BucketEntryTransportDeadReason::TooManyLostAnswers => {
                    write!(f, "Too many lost answers")
                }
                BucketEntryTransportDeadReason::NoPingResponse => write!(f, "No ping response"),
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum BucketEntryTransportUnreliableReason {
    FailedToSend,
    LostAnswers,
    NotSeenConsecutively,
    InUnreliablePingSpan,
}

impl fmt::Display for BucketEntryTransportUnreliableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            match self {
                BucketEntryTransportUnreliableReason::FailedToSend => write!(f, "UFSEND"),
                BucketEntryTransportUnreliableReason::LostAnswers => write!(f, "UALOST"),
                BucketEntryTransportUnreliableReason::NotSeenConsecutively => write!(f, "UNSEEN"),
                BucketEntryTransportUnreliableReason::InUnreliablePingSpan => write!(f, "UUPING"),
            }
        } else {
            match self {
                BucketEntryTransportUnreliableReason::FailedToSend => write!(f, "Failed to send"),
                BucketEntryTransportUnreliableReason::LostAnswers => write!(f, "Lost answers"),
                BucketEntryTransportUnreliableReason::NotSeenConsecutively => {
                    write!(f, "Not seen consecutively")
                }
                BucketEntryTransportUnreliableReason::InUnreliablePingSpan => {
                    write!(f, "In unreliable ping span")
                }
            }
        }
    }
}

/// Reason for a single transport's state. Punished is node-level and not
/// represented here.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum BucketEntryTransportStateReason {
    Dead(BucketEntryTransportDeadReason),
    Unreliable(BucketEntryTransportUnreliableReason),
    Reliable,
}

impl fmt::Display for BucketEntryTransportStateReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            match self {
                BucketEntryTransportStateReason::Dead(d) => write!(f, "{}", f.to_string(d)),
                BucketEntryTransportStateReason::Unreliable(u) => write!(f, "{}", f.to_string(u)),
                BucketEntryTransportStateReason::Reliable => write!(f, "RELIBL"),
            }
        } else {
            match self {
                BucketEntryTransportStateReason::Dead(d) => write!(f, "Dead({})", f.to_string(d)),
                BucketEntryTransportStateReason::Unreliable(u) => {
                    write!(f, "Unreliable({})", f.to_string(u))
                }
                BucketEntryTransportStateReason::Reliable => write!(f, "Reliable"),
            }
        }
    }
}

/// Per-transport state. Punished is node-level and not represented here.
// Do not change order here, it will mess up other sorts
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BucketEntryTransportState {
    Dead,
    Unreliable,
    Reliable,
}

impl BucketEntryTransportState {
    #[expect(dead_code)]
    pub fn is_alive(&self) -> bool {
        match self {
            BucketEntryTransportState::Dead => false,
            BucketEntryTransportState::Unreliable => true,
            BucketEntryTransportState::Reliable => true,
        }
    }
    #[expect(dead_code)]
    pub fn ordering(&self) -> usize {
        match self {
            BucketEntryTransportState::Dead => 0,
            BucketEntryTransportState::Unreliable => 1,
            BucketEntryTransportState::Reliable => 2,
        }
    }
}

impl From<BucketEntryTransportStateReason> for BucketEntryTransportState {
    fn from(value: BucketEntryTransportStateReason) -> Self {
        match value {
            BucketEntryTransportStateReason::Dead(_) => BucketEntryTransportState::Dead,
            BucketEntryTransportStateReason::Unreliable(_) => BucketEntryTransportState::Unreliable,
            BucketEntryTransportStateReason::Reliable => BucketEntryTransportState::Reliable,
        }
    }
}

/// Statistics for a single low-level transport on a BucketEntry.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct BucketEntryTransportStats {
    /// Rolling window collector for answers, rolled into `answer_stats` periodically.
    #[serde(skip)]
    pub answer_stats_accounting: AnswerStatsAccounting,
    /// Most recent rolled-up answer stats for this transport.
    #[serde(default)]
    pub answer_stats: AnswerStats,
    /// Consecutive lost answers since the last successful answer on this transport.
    pub recent_lost_answers: u32,
    /// Timestamp of the first answer in the current consecutive-seen run.
    pub first_consecutive_seen_ts: Option<Timestamp>,
    /// Last time we asked this transport a question.
    pub last_question_ts: Option<Timestamp>,
    /// Last time we heard back on this transport.
    pub last_seen_ts: Option<Timestamp>,
    /// Failed-to-send count on this transport since the last successful send.
    pub failed_to_send: u32,
}

impl BucketEntryTransportStats {
    /// Returns an unreliable reason for this transport's stats, or None if reliable.
    pub fn check_unreliable(
        &self,
        cur_ts: Timestamp,
        lost_answers_threshold: u32,
    ) -> Option<BucketEntryTransportUnreliableReason> {
        if self.failed_to_send > 0 {
            return Some(BucketEntryTransportUnreliableReason::FailedToSend);
        }
        if self.recent_lost_answers > lost_answers_threshold {
            return Some(BucketEntryTransportUnreliableReason::LostAnswers);
        }
        match self.first_consecutive_seen_ts {
            None => return Some(BucketEntryTransportUnreliableReason::NotSeenConsecutively),
            Some(ts) => {
                let seen_consecutively = cur_ts.duration_since(ts)
                    >= TimestampDuration::new_secs(UNRELIABLE_PING_SPAN_SECS);
                if !seen_consecutively {
                    return Some(BucketEntryTransportUnreliableReason::InUnreliablePingSpan);
                }
            }
        }
        None
    }

    /// Returns a dead reason for this transport's stats, or None if alive.
    pub fn check_dead(&self, cur_ts: Timestamp) -> Option<BucketEntryTransportDeadReason> {
        if self.failed_to_send >= NEVER_SEEN_PING_COUNT {
            return Some(BucketEntryTransportDeadReason::CanNotSend);
        }
        match self.last_seen_ts {
            None => {
                if self.recent_lost_answers >= NEVER_SEEN_PING_COUNT {
                    return Some(BucketEntryTransportDeadReason::TooManyLostAnswers);
                }
            }
            Some(ts) => {
                let not_seen = cur_ts.duration_since(ts)
                    >= TimestampDuration::new_secs(UNRELIABLE_PING_SPAN_SECS);
                let no_answers = self.recent_lost_answers
                    >= (UNRELIABLE_PING_SPAN_SECS / UNRELIABLE_PING_INTERVAL_SECS);
                if not_seen && no_answers {
                    return Some(BucketEntryTransportDeadReason::NoPingResponse);
                }
            }
        }
        None
    }

    /// Compute the state reason for this transport, given the unreliable
    /// lost-answers threshold to apply.
    pub fn state_reason(
        &self,
        cur_ts: Timestamp,
        lost_answers_threshold: u32,
    ) -> BucketEntryTransportStateReason {
        if let Some(dead_reason) = self.check_dead(cur_ts) {
            BucketEntryTransportStateReason::Dead(dead_reason)
        } else if let Some(unreliable_reason) =
            self.check_unreliable(cur_ts, lost_answers_threshold)
        {
            BucketEntryTransportStateReason::Unreliable(unreliable_reason)
        } else {
            BucketEntryTransportStateReason::Reliable
        }
    }

    pub fn state(
        &self,
        cur_ts: Timestamp,
        lost_answers_threshold: u32,
    ) -> BucketEntryTransportState {
        self.state_reason(cur_ts, lost_answers_threshold).into()
    }
}
