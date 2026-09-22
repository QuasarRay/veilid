use super::*;

// Pure timing rules for the Degraded overlay: fast entry, slow exit

fn ts(secs: u64) -> Timestamp {
    Timestamp::new(secs * 1_000_000)
}

fn base_clean() -> u32 {
    degraded_exit_clean_secs(0)
}

pub fn test_no_evidence_is_online() {
    assert_eq!(
        effective_online_state(OnlineState::Online, None, None, base_clean(), ts(100)),
        OnlineState::Online
    );
    assert_eq!(
        effective_online_state(
            OnlineState::Online,
            None,
            Some(ts(99)),
            base_clean(),
            ts(100)
        ),
        OnlineState::Online
    );
}

pub fn test_offline_dominates() {
    // Whatever the evidence says, the stored machine's Offline wins
    assert_eq!(
        effective_online_state(
            OnlineState::Offline,
            Some(ts(100)),
            Some(ts(101)),
            base_clean(),
            ts(100)
        ),
        OnlineState::Offline
    );
}

pub fn test_fresh_evidence_degrades() {
    let ev = ts(100);
    // Inside the clean window nothing else matters, success included
    assert_eq!(
        effective_online_state(
            OnlineState::Online,
            Some(ev),
            Some(ts(102)),
            base_clean(),
            ts(103)
        ),
        OnlineState::Degraded
    );
}

pub fn test_success_after_evidence_recovers() {
    let ev = ts(100);
    let after_clean = ts(100 + DEGRADED_EXIT_CLEAN_SECS as u64);
    assert_eq!(
        effective_online_state(
            OnlineState::Online,
            Some(ev),
            Some(ts(101)),
            base_clean(),
            after_clean
        ),
        OnlineState::Online
    );
}

pub fn test_stale_success_does_not_recover() {
    // A success predating the evidence proves nothing about recovery
    let ev = ts(100);
    let after_clean = ts(100 + DEGRADED_EXIT_CLEAN_SECS as u64);
    assert_eq!(
        effective_online_state(
            OnlineState::Online,
            Some(ev),
            Some(ts(99)),
            base_clean(),
            after_clean
        ),
        OnlineState::Degraded
    );
    // Success exactly AT the evidence is still not after it
    assert_eq!(
        effective_online_state(
            OnlineState::Online,
            Some(ev),
            Some(ev),
            base_clean(),
            after_clean
        ),
        OnlineState::Degraded
    );
}

pub fn test_no_success_holds_until_decay() {
    let ev = ts(100);
    let before_decay = ts(100 + DEGRADED_MAX_HOLD_SECS as u64 - 1);
    let at_decay = ts(100 + DEGRADED_MAX_HOLD_SECS as u64);
    assert_eq!(
        effective_online_state(
            OnlineState::Online,
            Some(ev),
            None,
            base_clean(),
            before_decay
        ),
        OnlineState::Degraded
    );
    // An idle node with no traffic to prove recovery decays back on its own
    assert_eq!(
        effective_online_state(OnlineState::Online, Some(ev), None, base_clean(), at_decay),
        OnlineState::Online
    );
}

pub fn test_clean_window_escalates_and_caps() {
    assert_eq!(degraded_exit_clean_secs(0), DEGRADED_EXIT_CLEAN_SECS);
    assert_eq!(degraded_exit_clean_secs(1), DEGRADED_EXIT_CLEAN_SECS * 2);
    assert_eq!(degraded_exit_clean_secs(20), DEGRADED_EXIT_CLEAN_MAX_SECS);
    // The escalated window must stay under the idle decay or it could never expire
    const { assert!(DEGRADED_EXIT_CLEAN_MAX_SECS < DEGRADED_MAX_HOLD_SECS) };
}

pub fn test_escalated_window_closes_the_gap() {
    // A gap after the success lets the base window open an Online hole before the
    // next burst of evidence lands
    let ev = ts(100);
    let success = ts(101);
    let in_gap = ts(100 + DEGRADED_EXIT_CLEAN_SECS as u64 + 1);
    assert_eq!(
        effective_online_state(
            OnlineState::Online,
            Some(ev),
            Some(success),
            base_clean(),
            in_gap
        ),
        OnlineState::Online
    );
    assert_eq!(
        effective_online_state(
            OnlineState::Online,
            Some(ev),
            Some(success),
            degraded_exit_clean_secs(1),
            in_gap
        ),
        OnlineState::Degraded
    );
}

fn node(n: u8) -> NodeId {
    let mut b = [0u8; 32];
    b[0] = n;
    NodeId::new(CRYPTO_KIND_VLD0, BareNodeId::new(&b))
}

fn broad_failure(ft: FramingType, first: u8, count: u8, sent_ts: Timestamp) -> OnlineEvent {
    let ids: Vec<NodeId> = (first..first + count).map(node).collect();
    OnlineEvent::Failure {
        live_node_ids: ids.clone(),
        fresh_node_ids: ids,
        responsive_count: 0,
        sent_ts,
        framing_type: ft,
    }
}

pub fn test_recovery_clears_evidence_window() {
    // A recovered domain must not re-degrade on a single failure: the evidence window
    // (10s) outlives the clean period (5s), so the old entries have to go with the episode
    let mut pd = OnlineDetectionPerDomain::default();
    let framing = FramingTypeSet::all();
    let threshold = OFFLINE_DETECTION_FAILURE_THRESHOLD_CONNECTION as u8;

    // Enough fresh failures on every framing type: degraded
    for ft in framing {
        let ev = broad_failure(ft, 1, threshold, ts(10));
        // Offline needs the same breadth sustained; here only the degraded overlay matters
        let _ = OnlineDetector::process_online_event(&mut pd, &ev, framing, ts(10));
    }
    assert_eq!(pd.last_degraded_evidence_ts, Some(ts(10)));
    assert!(OnlineDetector::commit_effective(&mut pd, None, ts(10)).is_some());
    assert_eq!(pd.effective_state, OnlineState::Degraded);

    // A round trip after the evidence plus the clean period: recovered, window gone
    pd.last_success_ts = Some(ts(12));
    let transition = OnlineDetector::commit_effective(&mut pd, None, ts(16));
    assert_eq!(transition.map(|t| t.1), Some(OnlineState::Online));
    assert!(pd.windowed_failures.values().all(BTreeMap::is_empty));
    assert_eq!(pd.last_degraded_evidence_ts, None);

    // One more failure per framing type is not breadth
    for ft in framing {
        let ev = broad_failure(ft, 100, 1, ts(17));
        let _ = OnlineDetector::process_online_event(&mut pd, &ev, framing, ts(17));
    }
    assert_eq!(pd.last_degraded_evidence_ts, None);
    assert!(OnlineDetector::commit_effective(&mut pd, None, ts(17)).is_none());
    assert_eq!(pd.effective_state, OnlineState::Online);
}

pub fn test_stall_is_credited_as_untestable() {
    // A 100s stall noticed at t=200 is the interval (100, 200): the entries
    // could not be tested, and the thaw reads as a reattach
    let mut pd = OnlineDetectionPerDomain::default();
    OnlineDetector::credit_stall(&mut pd, ts(200), TimestampDuration::new_secs(100));
    assert_eq!(
        pd.recent_offline_intervals.back(),
        Some(&(ts(100), ts(200)))
    );

    // Degraded going into the stall: that window closes at the freeze and restarts
    // at the thaw, and the stall between them is untestable
    let mut pd = OnlineDetectionPerDomain::default();
    pd.degraded_started_ts = Some(ts(50));
    assert_eq!(
        OnlineDetector::credit_stall(&mut pd, ts(200), TimestampDuration::new_secs(100)),
        Some((ts(100), ts(200)))
    );
    assert_eq!(
        pd.recent_degraded_intervals.back(),
        Some(&(ts(50), ts(100)))
    );
    assert_eq!(pd.degraded_started_ts, Some(ts(200)));

    // Degraded going into the stall and recovered at the thaw before this tick: the
    // recorded window is cut back to the freeze, and the stall is credited up to the
    // failure storm that followed
    let mut pd = OnlineDetectionPerDomain::default();
    pd.recent_degraded_intervals.push_back((ts(90), ts(199)));
    pd.degraded_started_ts = Some(ts(199));
    assert_eq!(
        OnlineDetector::credit_stall(&mut pd, ts(200), TimestampDuration::new_secs(100)),
        Some((ts(100), ts(199)))
    );
    assert_eq!(
        pd.recent_degraded_intervals.back(),
        Some(&(ts(90), ts(100)))
    );

    // Offline going into the stall already credits it: nothing more is recorded
    let mut pd = OnlineDetectionPerDomain::default();
    pd.offline_started_ts = Some(ts(50));
    assert_eq!(
        OnlineDetector::credit_stall(&mut pd, ts(200), TimestampDuration::new_secs(100)),
        None
    );
    assert!(pd.recent_offline_intervals.is_empty());

    // A recorded interval ending inside the stall clips the start rather than overlapping
    let mut pd = OnlineDetectionPerDomain::default();
    pd.recent_offline_intervals.push_back((ts(80), ts(150)));
    OnlineDetector::credit_stall(&mut pd, ts(200), TimestampDuration::new_secs(100));
    assert_eq!(
        pd.recent_offline_intervals.back(),
        Some(&(ts(150), ts(200)))
    );

    // The failure storm at the thaw took the domain Degraded before this tick ran:
    // the stall is still credited, up to where that interval began
    let mut pd = OnlineDetectionPerDomain::default();
    pd.degraded_started_ts = Some(ts(199));
    assert_eq!(
        OnlineDetector::credit_stall(&mut pd, ts(200), TimestampDuration::new_secs(100)),
        Some((ts(100), ts(199)))
    );
    assert_eq!(
        pd.recent_offline_intervals.back(),
        Some(&(ts(100), ts(199)))
    );

    // A thaw-time offline blip already recorded past the stall clips the end
    // and the credit slots in before it
    let mut pd = OnlineDetectionPerDomain::default();
    pd.recent_offline_intervals.push_back((ts(198), ts(199)));
    pd.degraded_started_ts = Some(ts(199));
    OnlineDetector::credit_stall(&mut pd, ts(200), TimestampDuration::new_secs(100));
    assert_eq!(
        pd.recent_offline_intervals
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![(ts(100), ts(198)), (ts(198), ts(199))]
    );

    // The degraded overlay is untouched: the stall is evidence at the thaw, not before
    let mut pd = OnlineDetectionPerDomain::default();
    OnlineDetector::credit_stall(&mut pd, ts(200), TimestampDuration::new_secs(100));
    assert!(OnlineDetector::commit_effective(&mut pd, Some(ts(200)), ts(200)).is_some());
    assert_eq!(pd.degraded_started_ts, Some(ts(200)));
}

pub fn test_credit_is_kept_by_count() {
    // Freezes far older than the reliable ping span still credit a streak that
    // has had no chance to complete; only the count bounds the deque
    let mut pd = OnlineDetectionPerDomain::default();
    for i in 0..70u64 {
        OnlineDetector::credit_stall(&mut pd, ts(100 * i + 10), TimestampDuration::new_secs(5));
    }
    assert_eq!(pd.recent_offline_intervals.len(), 64);
    assert_eq!(
        pd.recent_offline_intervals.front(),
        Some(&(ts(605), ts(610)))
    );
    assert_eq!(
        pd.recent_offline_intervals.back(),
        Some(&(ts(6905), ts(6910)))
    );
}

pub fn test_all() {
    test_credit_is_kept_by_count();
    test_stall_is_credited_as_untestable();
    test_recovery_clears_evidence_window();
    test_no_evidence_is_online();
    test_offline_dominates();
    test_fresh_evidence_degrades();
    test_success_after_evidence_recovers();
    test_stale_success_does_not_recover();
    test_no_success_holds_until_decay();
    test_clean_window_escalates_and_caps();
    test_escalated_window_closes_the_gap();
}
