use std::sync::atomic::AtomicU64;

use super::*;

/// Atomic wrapper for optional timestamps used in structs so we can avoid locks
/// for LRU and similar operations
#[derive(Debug, Default, Serialize, Deserialize, JsonSchema, GetSize)]
#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    derive(Tsify),
    tsify(from_wasm_abi, into_wasm_abi)
)]
#[cfg_attr(feature = "json-camel-case", serde(rename_all = "camelCase"))]
#[must_use]
#[serde(from = "Option<Timestamp>", into = "Option<Timestamp>")]
pub struct AtomicOptionTimestamp(AtomicU64);

impl Clone for AtomicOptionTimestamp {
    fn clone(&self) -> Self {
        Self(AtomicU64::new(self.0.load(Ordering::Acquire)))
    }
}

impl fmt::Display for AtomicOptionTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.get()
                .map(|t| t.to_string())
                .unwrap_or("None".to_string())
        )
    }
}

impl AtomicOptionTimestamp {
    pub fn new(opt_ts: Option<Timestamp>) -> Self {
        Self(AtomicU64::new(opt_ts.map(|t| t.as_u64()).unwrap_or(0)))
    }

    pub fn none() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn now() -> Self {
        Self::new(Some(Timestamp::now()))
    }

    pub fn now_non_decreasing() -> Self {
        Self::new(Some(Timestamp::now_non_decreasing()))
    }

    pub fn now_increasing() -> Self {
        Self::new(Some(Timestamp::now_increasing()))
    }

    pub fn get(&self) -> Option<Timestamp> {
        let ts = self.0.load(Ordering::Acquire);
        if ts == 0 {
            None
        } else {
            Some(Timestamp::new(ts))
        }
    }

    pub fn set(&self, opt_t: Option<Timestamp>) {
        self.0
            .store(opt_t.map(|t| t.as_u64()).unwrap_or(0), Ordering::Release);
    }

    /// Fetch and update the optional timestamp atomically
    ///
    /// Parameters:
    /// - f: A function that takes the current optional timestamp and returns an optional new optional timestamp
    ///
    /// Returns:
    /// - The new optional timestamp if the update was successful, otherwise the current optional timestamp
    pub fn fetch_update(
        &self,
        mut f: impl FnMut(Option<Timestamp>) -> Option<Option<Timestamp>>,
    ) -> Result<Option<Timestamp>, Option<Timestamp>> {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                f(if v == 0 {
                    None
                } else {
                    Some(Timestamp::new(v))
                })
                .map(|opt_v| opt_v.map(|v| v.as_u64()).unwrap_or(0))
            })
            .map(|opt_v| {
                if opt_v == 0 {
                    None
                } else {
                    Some(Timestamp::new(opt_v))
                }
            })
            .map_err(|opt_v| {
                if opt_v == 0 {
                    None
                } else {
                    Some(Timestamp::new(opt_v))
                }
            })
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
    ) -> Option<ExpirationState> {
        let existing_ts = self.get()?;
        if cur_ts.duration_since(existing_ts) >= expiration {
            Some(ExpirationState::Dead)
        } else {
            Some(ExpirationState::Live)
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
            .fetch_update(move |opt_existing_ts| {
                if let Some(existing_ts) = opt_existing_ts {
                    if cur_ts.duration_since(existing_ts) >= expiration {
                        None
                    } else {
                        Some(Some(cur_ts))
                    }
                } else {
                    Some(Some(cur_ts))
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

impl From<Timestamp> for AtomicOptionTimestamp {
    fn from(t: Timestamp) -> Self {
        Self::new(Some(t))
    }
}

impl From<Option<Timestamp>> for AtomicOptionTimestamp {
    fn from(opt_t: Option<Timestamp>) -> Self {
        Self::new(opt_t)
    }
}

impl From<AtomicOptionTimestamp> for Option<Timestamp> {
    fn from(at: AtomicOptionTimestamp) -> Self {
        at.get()
    }
}

impl From<&AtomicOptionTimestamp> for Option<Timestamp> {
    fn from(at: &AtomicOptionTimestamp) -> Self {
        at.get()
    }
}
