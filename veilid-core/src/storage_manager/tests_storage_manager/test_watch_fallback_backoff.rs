use super::*;

/// The fallback change inspection fires on SILENCE, and silence is the normal
/// condition of a record nobody is writing, so a flat interval inspects a quiet
/// watch forever. The interval has to grow while inspections keep coming back
/// empty, and snap back on any evidence that the watch is live or has moved.
///
/// These pin the pure state machine. The network behaviour it drives is covered by
/// veilid-python's watch battery.
fn make_params(subkeys: ValueSubkeyRangeSet) -> OutboundWatchParameters {
    OutboundWatchParameters {
        expiration: Timestamp::new(0),
        count: u32::MAX,
        subkeys,
        opt_watcher: None,
        safety_selection: SafetySelection::Unsafe(Sequencing::PreferOrdered),
    }
}

/// An unproductive inspection doubles the wait, up to the ceiling.
fn test_backoff_doubles_until_capped() {
    let mut state = OutboundWatchState::new(make_params(ValueSubkeyRangeSet::single(0)));
    let per_node_states = HashMap::new();

    let base = state.fallback_inspect_interval();
    assert_eq!(base, TimestampDuration::new_secs(30));

    // Each empty inspection doubles the interval
    let mut expected = base;
    for _ in 0..4 {
        state.edit(&per_node_states, |editor| {
            editor.back_off_fallback_inspect();
        });
        expected = TimestampDuration::new(expected.as_u64() * 2);
        assert_eq!(state.fallback_inspect_interval(), expected);
    }

    // And stops at the ceiling rather than growing without bound
    for _ in 0..20 {
        state.edit(&per_node_states, |editor| {
            editor.back_off_fallback_inspect();
        });
    }
    assert_eq!(
        state.fallback_inspect_interval(),
        TimestampDuration::new_secs(600)
    );
}

/// A delivered ValueChanged proves the watch works, so the next miss is worth
/// noticing promptly. Same for the watch moving to different nodes or subkeys.
fn test_evidence_resets_backoff() {
    let per_node_states = HashMap::new();

    for reset in [
        // A delivered change
        (|editor: &mut OutboundWatchStateEditor| editor.touch_value_changed(Timestamp::new(1)))
            as fn(&mut OutboundWatchStateEditor),
        // A productive inspection, or the watch's nodes/params moving
        |editor: &mut OutboundWatchStateEditor| editor.reset_fallback_inspect_backoff(),
    ] {
        let mut state = OutboundWatchState::new(make_params(ValueSubkeyRangeSet::single(0)));
        state.edit(&per_node_states, |editor| {
            editor.back_off_fallback_inspect();
            editor.back_off_fallback_inspect();
        });
        assert_ne!(
            state.fallback_inspect_interval(),
            TimestampDuration::new_secs(30)
        );

        state.edit(&per_node_states, reset);
        assert_eq!(
            state.fallback_inspect_interval(),
            TimestampDuration::new_secs(30),
            "evidence the watch is live should restore the base interval"
        );
    }
}

/// The backed-off interval is what `needs_fallback_inspect` actually waits for -
/// a backoff nothing consults would be decorative.
fn test_needs_fallback_inspect_honours_backoff() {
    let mut state = OutboundWatchState::new(make_params(ValueSubkeyRangeSet::single(0)));
    let per_node_states = HashMap::new();

    // Establishment stamps the reference time, so nothing is due immediately
    assert!(!state.needs_fallback_inspect(Timestamp::new(0)));

    // Far enough out, the base interval is due
    let base_due = Timestamp::now_non_decreasing().later(TimestampDuration::new_secs(31));
    assert!(state.needs_fallback_inspect(base_due));

    // After one empty inspection the same moment is no longer due
    state.edit(&per_node_states, |editor| {
        editor.back_off_fallback_inspect();
    });
    assert!(
        !state.needs_fallback_inspect(base_due),
        "a backed-off watch should not be due at the base interval"
    );
    assert!(state.needs_fallback_inspect(
        Timestamp::now_non_decreasing().later(TimestampDuration::new_secs(61))
    ));
}

/// A watch that is wanted but has never established has no state to keep a timer
/// in. It still needs covering, because the app asked for it and core owns
/// delivery - but at the slow rate, since reconcile is already retrying and a
/// record no node serves has nothing to report.
fn test_unestablished_watch_is_inspected_slowly() {
    let record_key = RecordKey::from_opaque(
        OpaqueRecordKey::new(CRYPTO_KIND_VLD0, BareOpaqueRecordKey::new(&[0u8; 32])),
        None,
    );
    let subkeys = ValueSubkeyRangeSet::single(7);
    let mut outbound_watch = OutboundWatch::new(record_key, make_params(subkeys.clone()));
    let per_node_states = HashMap::new();

    // Never inspected, so it is due at once, over the DESIRED subkeys
    assert_eq!(
        outbound_watch.needs_fallback_inspect(Timestamp::new(0)),
        Some(subkeys.clone())
    );

    let now = Timestamp::now_non_decreasing();
    outbound_watch.touch_fallback_inspect(&per_node_states, now);

    // Not due again at the established-watch cadence
    assert_eq!(
        outbound_watch.needs_fallback_inspect(now.later(TimestampDuration::new_secs(60))),
        None,
        "an unestablished watch should not inspect at the 30s cadence"
    );
    assert_eq!(
        outbound_watch.needs_fallback_inspect(now.later(TimestampDuration::new_secs(601))),
        Some(subkeys)
    );

    // A cancelled watch - no state and no desired - is inspected by nobody
    outbound_watch.set_desired(None);
    assert_eq!(
        outbound_watch.needs_fallback_inspect(now.later(TimestampDuration::new_secs(601))),
        None
    );
}

pub fn test_all() {
    test_backoff_doubles_until_capped();
    test_evidence_resets_backoff();
    test_needs_fallback_inspect_honours_backoff();
    test_unestablished_watch_is_inspected_slowly();
}
