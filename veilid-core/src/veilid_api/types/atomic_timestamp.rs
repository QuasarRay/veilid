use super::*;
use std::sync::atomic::AtomicU64;

/// Atomic wrapper for timestamps used in structs so we can avoid locks
/// for LRU and similar operations
#[derive(Debug, Default, Serialize, Deserialize, JsonSchema, GetSize)]
#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    derive(Tsify),
    tsify(from_wasm_abi, into_wasm_abi)
)]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
#[serde(from = "Timestamp", into = "Timestamp")]
#[must_use]
pub struct AtomicTimestamp(AtomicU64);

impl Clone for AtomicTimestamp {
    fn clone(&self) -> Self {
        Self(AtomicU64::new(self.0.load(Ordering::Acquire)))
    }
}

impl fmt::Display for AtomicTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

impl AtomicTimestamp {
    pub fn now() -> Self {
        Self::new(Timestamp::now())
    }

    pub fn now_non_decreasing() -> Self {
        Self::new(Timestamp::now_non_decreasing())
    }

    pub fn now_increasing() -> Self {
        Self::new(Timestamp::now_increasing())
    }

    pub fn new(t: Timestamp) -> Self {
        Self(AtomicU64::new(t.as_u64()))
    }

    pub fn get(&self) -> Timestamp {
        Timestamp::new(self.0.load(Ordering::Acquire))
    }

    pub fn set(&self, t: Timestamp) {
        self.0.store(t.as_u64(), Ordering::Release);
    }

    /// Fetch and update the timestamp atomically
    ///
    /// Parameters:
    /// - f: A function that takes the current timestamp and returns an optional new timestamp
    ///
    /// Returns:
    /// - The new timestamp if the update was successful, otherwise the current timestamp
    pub fn fetch_update(
        &self,
        mut f: impl FnMut(Timestamp) -> Option<Timestamp>,
    ) -> Result<Timestamp, Timestamp> {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                f(Timestamp::new(v)).map(|v| v.as_u64())
            })
            .map(Timestamp::new)
            .map_err(Timestamp::new)
    }

    /// Check if a timestamp has expired atomically
    ///
    /// Parameters:
    /// - cur_ts: The current timestamp
    /// - expiration: The expiration duration
    ///
    /// Returns:
    /// - true if the timestamp has expired, false if it has not
    pub fn expiration_state(
        &self,
        cur_ts: Timestamp,
        expiration: TimestampDuration,
    ) -> ExpirationState {
        let existing_ts = self.get();
        if cur_ts.duration_since(existing_ts) >= expiration {
            ExpirationState::Dead
        } else {
            ExpirationState::Live
        }
    }

    /// Check if a timestamp is expired and update it to the current time if it is not, atomically.
    /// Useful for LRU caching.
    ///
    /// Parameters:
    /// - cur_ts: The current timestamp
    /// - expiration: The expiration duration
    ///
    /// Returns:
    /// - true if the timestamp was updated, false if it was expired
    pub fn update_if_not_expired(
        &self,
        cur_ts: Timestamp,
        expiration: TimestampDuration,
    ) -> ExpirationState {
        let updated = self
            .fetch_update(move |existing_ts| {
                // If the existing timestamp is older than the expiration timestamp,
                // then no change is made and we return false
                // Otherwise, we update the timestamp and return true
                if cur_ts.duration_since(existing_ts) >= expiration {
                    None
                } else {
                    Some(cur_ts)
                }
            })
            .is_ok();
        if updated {
            ExpirationState::Live
        } else {
            ExpirationState::Dead
        }
    }
}

impl From<Timestamp> for AtomicTimestamp {
    fn from(t: Timestamp) -> Self {
        Self::new(t)
    }
}

impl From<AtomicTimestamp> for Timestamp {
    fn from(at: AtomicTimestamp) -> Self {
        at.get()
    }
}

impl From<&AtomicTimestamp> for Timestamp {
    fn from(at: &AtomicTimestamp) -> Self {
        at.get()
    }
}
