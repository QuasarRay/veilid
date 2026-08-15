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

pub fn test_all() {
    test_no_evidence_is_online();
    test_offline_dominates();
    test_fresh_evidence_degrades();
    test_success_after_evidence_recovers();
    test_stale_success_does_not_recover();
    test_no_success_holds_until_decay();
    test_clean_window_escalates_and_caps();
    test_escalated_window_closes_the_gap();
}
