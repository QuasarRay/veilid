use super::*;

/// The fallback change inspection fires on SILENCE, and silence is the normal
/// condition of a record nobody is writing, so a flat interval inspects a quiet
/// watch forever. The interval has to grow while inspections keep coming back
/// empty, and snap back on evidence that the watch is live, has gained a node, or
/// has changed subkeys.
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

/// An inspection answered with nothing newer doubles the wait, up to the ceiling.
fn test_backoff_doubles_until_capped() {
    let mut state = OutboundWatchState::new(make_params(ValueSubkeyRangeSet::single(0)));
    let per_node_states = HashMap::new();

    let base = state.fallback_inspect_interval();
    assert_eq!(base, TimestampDuration::new_secs(30));

    // Each empty inspection doubles the interval
    let mut expected = base;
    for _ in 0..2 {
        state.edit(&per_node_states, |editor| {
            editor.back_off_fallback_inspect()
        });
        expected = TimestampDuration::new(expected.as_u64() * 2);
        assert_eq!(state.fallback_inspect_interval(), expected);
    }

    // And stops at the ceiling rather than growing without bound
    for _ in 0..20 {
        state.edit(&per_node_states, |editor| {
            editor.back_off_fallback_inspect()
        });
    }
    assert_eq!(
        state.fallback_inspect_interval(),
        WATCH_FALLBACK_INSPECT_MAX_INTERVAL
    );
}

/// The interval persists with the watch state, so one saved under an older, higher
/// ceiling must read as today's ceiling rather than hold the watch to it.
fn test_saved_interval_above_ceiling_reads_capped() {
    let per_node_states = HashMap::new();
    let mut state = OutboundWatchState::new(make_params(ValueSubkeyRangeSet::single(0)));
    state.edit(&per_node_states, |editor| {
        editor.back_off_fallback_inspect()
    });

    let mut saved = serde_json::to_value(&state).unwrap();
    saved["opt_fallback_inspect_interval"] = serde_json::Value::from("600000000");
    let mut state: OutboundWatchState = serde_json::from_value(saved).unwrap();
    assert_eq!(
        state.fallback_inspect_interval(),
        WATCH_FALLBACK_INSPECT_MAX_INTERVAL
    );

    state.edit(&per_node_states, |editor| {
        editor.back_off_fallback_inspect()
    });
    assert_eq!(
        state.fallback_inspect_interval(),
        WATCH_FALLBACK_INSPECT_MAX_INTERVAL
    );
}

/// A delivered ValueChanged proves the watch works, so the next miss is worth
/// noticing promptly. Same for the watch gaining a node or changing subkeys.
fn test_evidence_resets_backoff() {
    let per_node_states = HashMap::new();

    for reset in [
        // A delivered change
        (|editor: &mut OutboundWatchStateEditor| editor.touch_value_changed(Timestamp::new(1)))
            as fn(&mut OutboundWatchStateEditor),
        // A productive inspection, a gained node, or changed params
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
        editor.back_off_fallback_inspect()
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
/// delivery, at an established watch's longest wait since reconcile is already
/// retrying.
fn test_unestablished_watch_is_inspected_at_the_ceiling() {
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
        outbound_watch.needs_fallback_inspect(now.later(TimestampDuration::new_secs(121))),
        Some(subkeys)
    );

    // A cancelled watch - no state and no desired - is inspected by nobody
    outbound_watch.set_desired(None);
    assert_eq!(
        outbound_watch.needs_fallback_inspect(now.later(TimestampDuration::new_secs(121))),
        None
    );
}

/// Leaving Degraded re-inspects every watch, the way coming back online does; no
/// other transition, and no other routing domain, may.
fn test_recovery_from_degraded_reinspects_watches() {
    let evt = |routing_domain, old_state, new_state| OnlineStateChangeEvent {
        routing_domain,
        old_state,
        new_state,
    };
    assert!(StorageManager::online_state_change_reinspects_watches(
        &evt(
            RoutingDomain::PublicInternet,
            OnlineState::Degraded,
            OnlineState::Online
        )
    ));
    for (domain, old_state, new_state) in [
        (
            RoutingDomain::PublicInternet,
            OnlineState::Online,
            OnlineState::Degraded,
        ),
        (
            RoutingDomain::PublicInternet,
            OnlineState::Offline,
            OnlineState::Online,
        ),
        (
            RoutingDomain::PublicInternet,
            OnlineState::Degraded,
            OnlineState::Offline,
        ),
        (
            RoutingDomain::LocalNetwork,
            OnlineState::Degraded,
            OnlineState::Online,
        ),
    ] {
        assert!(
            !StorageManager::online_state_change_reinspects_watches(&evt(
                domain, old_state, new_state
            )),
            "{:?} {:?}->{:?} must not re-inspect",
            domain,
            old_state,
            new_state
        );
    }
}

/// Offline, nothing gets through, so watch network work holds rather than spend
/// itself failing; degraded round trips still complete, so it runs.
fn test_watch_network_work_holds_only_while_offline() {
    assert!(StorageManager::holds_watch_network_work(
        OnlineState::Offline
    ));
    assert!(!StorageManager::holds_watch_network_work(
        OnlineState::Degraded
    ));
    assert!(!StorageManager::holds_watch_network_work(
        OnlineState::Online
    ));
}

/// A reconcile that nodes answered only with refusals (no copy, usually nothing
/// written yet) waits the slow interval; one nobody answered learned nothing about the
/// record and retries, as does any reconcile still short of consensus.
fn test_reconcile_retries_silence_not_refusals() {
    let retry = RECONCILE_OUTBOUND_WATCHES_RETRY_INTERVAL;
    let slow = RECONCILE_OUTBOUND_WATCHES_INTERVAL;
    assert_eq!(StorageManager::next_reconcile_interval(true, 0, 0), retry);
    assert_eq!(StorageManager::next_reconcile_interval(true, 0, 3), slow);
    assert_eq!(StorageManager::next_reconcile_interval(true, 2, 1), retry);
    assert_eq!(StorageManager::next_reconcile_interval(false, 5, 0), slow);
}

pub fn test_all() {
    test_backoff_doubles_until_capped();
    test_recovery_from_degraded_reinspects_watches();
    test_saved_interval_above_ceiling_reads_capped();
    test_evidence_resets_backoff();
    test_needs_fallback_inspect_honours_backoff();
    test_unestablished_watch_is_inspected_at_the_ceiling();
    test_watch_network_work_holds_only_while_offline();
    test_reconcile_retries_silence_not_refusals();
}
