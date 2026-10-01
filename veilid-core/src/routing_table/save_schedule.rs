use super::*;

/// Quiet time after a change worth saving before it is saved
const SAVE_SETTLE: TimestampDuration = TimestampDuration::new_secs(5);
/// Least time between saves driven by changes
const SAVE_MIN_INTERVAL: TimestampDuration = TimestampDuration::new_secs(10);
/// Least time between saves in the background, where the process may be frozen within seconds
#[cfg(feature = "app-lifecycle")]
const BACKGROUND_SAVE_MIN_INTERVAL: TimestampDuration = TimestampDuration::new_secs(5);
/// Longest the table goes unsaved, for the per-entry stats no change accounts for
const SAVE_PERIOD: TimestampDuration = TimestampDuration::new_secs(300);
/// Entry state changes that together make a change worth saving
const SAVE_STATE_CHANGE_COUNT: usize = 16;

/// Why the routing table was saved
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaveReason {
    /// Changes worth saving settled
    Changed,
    /// The app went to the background, or something changed while it was there
    #[cfg(feature = "app-lifecycle")]
    Background,
    /// Nothing else saved it for a while
    Periodic,
    /// A bootstrap finished
    Bootstrap,
    /// The node detached with changes unsaved
    Detach,
    /// The node shut down
    Terminate,
}

/// When the routing table next goes to disk.
///
/// A new entry, a changed peer info, or enough entries changing state is worth saving once the
/// changes settle. Per-entry stats change too often to drive saves and ride along on the
/// periodic one. In the background the platform may freeze or kill the process within seconds,
/// so changes there are saved without waiting for them to settle.
#[derive(Debug)]
pub(crate) struct SaveSchedule {
    /// When the last save started
    last_save_ts: Timestamp,
    /// When the periodic save's clock started: the last save, or the app's return from the background
    period_start_ts: Timestamp,
    /// The latest change worth saving since the last save
    last_change_ts: Option<Timestamp>,
    /// Entry state changes since the last save
    state_changes: usize,
    /// Whether the app is in the background
    #[cfg(feature = "app-lifecycle")]
    background: bool,
}

impl SaveSchedule {
    pub fn new(cur_ts: Timestamp) -> Self {
        Self {
            last_save_ts: cur_ts,
            period_start_ts: cur_ts,
            last_change_ts: None,
            state_changes: 0,
            #[cfg(feature = "app-lifecycle")]
            background: false,
        }
    }

    /// A change worth saving
    pub fn changed(&mut self, cur_ts: Timestamp) {
        self.last_change_ts = Some(cur_ts);
    }

    /// An entry changed state; enough of them make a change worth saving
    pub fn state_changed(&mut self, cur_ts: Timestamp) {
        self.state_changes += 1;
        if self.state_changes >= SAVE_STATE_CHANGE_COUNT {
            self.changed(cur_ts);
        }
    }

    /// The app moved in or out of the background. Moving in is a change worth saving. Moving
    /// out restarts the periodic clock: a frozen process has nothing to add to what it saved.
    #[cfg(feature = "app-lifecycle")]
    pub fn set_background(&mut self, background: bool, cur_ts: Timestamp) {
        match (self.background, background) {
            (false, true) => self.changed(cur_ts),
            (true, false) => self.period_start_ts = cur_ts,
            _ => {}
        }
        self.background = background;
    }

    /// Whether the app is in the background
    #[cfg(feature = "app-lifecycle")]
    pub fn is_background(&self) -> bool {
        self.background
    }

    /// Whether a change worth saving is unsaved
    pub fn is_dirty(&self) -> bool {
        self.last_change_ts.is_some()
    }

    /// Why a save is due, if one is
    pub fn due(&self, cur_ts: Timestamp) -> Option<SaveReason> {
        let since_save = cur_ts.duration_since(self.last_save_ts);
        let periodic = (cur_ts.duration_since(self.period_start_ts) >= SAVE_PERIOD)
            .then_some(SaveReason::Periodic);
        let Some(last_change_ts) = self.last_change_ts else {
            return periodic;
        };
        #[cfg(feature = "app-lifecycle")]
        if self.background {
            return (since_save >= BACKGROUND_SAVE_MIN_INTERVAL)
                .then_some(SaveReason::Background)
                .or(periodic);
        }
        (cur_ts.duration_since(last_change_ts) >= SAVE_SETTLE && since_save >= SAVE_MIN_INTERVAL)
            .then_some(SaveReason::Changed)
            .or(periodic)
    }

    /// A save is starting, and covers every change so far
    pub fn saving(&mut self, cur_ts: Timestamp) {
        self.last_save_ts = cur_ts;
        self.period_start_ts = cur_ts;
        self.last_change_ts = None;
        self.state_changes = 0;
    }
}
