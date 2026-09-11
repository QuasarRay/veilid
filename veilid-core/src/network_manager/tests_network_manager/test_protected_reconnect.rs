use super::connection_manager::{ProtectedDropAction, ProtectedDropTracker};
use super::*;

/// A peer that accepts a handshake and then drops us must not be able to drive reconnects
/// indefinitely. Before this policy was fixed the breaker reset its own counter when it tripped,
/// so three of every four drops reconnected, forever and with no delay.
pub fn test_reconnect_storm_is_bounded() {
    let t0 = Timestamp::new(1_000_000_000);
    let mut tracker = ProtectedDropTracker::new(t0);

    // Drops arriving as fast as a handshake completes, all well inside one span
    let mut reconnects = 0usize;
    let mut trips = 0usize;
    for i in 0..1000u64 {
        let ts = Timestamp::new(t0.as_u64() + i * 1_000);
        match tracker.record_drop(ts) {
            ProtectedDropAction::Reconnect => reconnects += 1,
            ProtectedDropAction::HoldOff { tripped_now } => {
                if tripped_now {
                    trips += 1;
                }
            }
        }
    }

    assert_eq!(
        reconnects, 2,
        "one span must allow at most PROTECTED_CONNECTION_DROP_COUNT-1 reconnects"
    );
    assert_eq!(
        trips, 1,
        "the hold-off should be reported once, not per drop"
    );
}

/// A connection that lived a while and then dropped is not a storm, and must still reconnect.
pub fn test_span_rolls_so_occasional_drops_still_reconnect() {
    let t0 = Timestamp::new(1_000_000_000);
    let mut tracker = ProtectedDropTracker::new(t0);

    let minute_us = 60_000_000u64;
    for i in 1..=50u64 {
        let ts = Timestamp::new(t0.as_u64() + i * minute_us);
        assert_eq!(
            tracker.record_drop(ts),
            ProtectedDropAction::Reconnect,
            "a drop outside the span starts a new one and must reconnect (drop {i})"
        );
        assert_eq!(tracker.drops_in_span(), 1);
    }
}

/// The boundary itself: two fast drops then a pause long enough to roll the span.
pub fn test_a_pause_clears_the_breaker() {
    let t0 = Timestamp::new(1_000_000_000);
    let mut tracker = ProtectedDropTracker::new(t0);

    assert_eq!(tracker.record_drop(t0), ProtectedDropAction::Reconnect);
    assert_eq!(
        tracker.record_drop(Timestamp::new(t0.as_u64() + 1_000)),
        ProtectedDropAction::Reconnect
    );
    assert!(matches!(
        tracker.record_drop(Timestamp::new(t0.as_u64() + 2_000)),
        ProtectedDropAction::HoldOff { .. }
    ));

    // Past the span from its start, so the next drop begins a fresh one
    let after = Timestamp::new(t0.as_u64() + PROTECTED_CONNECTION_DROP_SPAN.as_u64() + 1);
    assert_eq!(tracker.record_drop(after), ProtectedDropAction::Reconnect);
}

pub fn test_all() {
    test_reconnect_storm_is_bounded();
    test_span_rolls_so_occasional_drops_still_reconnect();
    test_a_pause_clears_the_breaker();
}
