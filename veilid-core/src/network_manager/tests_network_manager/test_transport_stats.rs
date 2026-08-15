use super::*;

fn now() -> Timestamp {
    // Far enough from zero to subtract windows without underflow
    Timestamp::new(1_000_000_000u64)
}

fn secs_ago(secs: u64) -> Timestamp {
    Timestamp::new(now().as_u64() - secs * 1_000_000u64)
}

fn peer(n: u8) -> TransportPeerKey {
    let mut b = [0u8; 32];
    b[0] = n;
    TransportPeerKey::Node(NodeId::new(CRYPTO_KIND_VLD0, BareNodeId::new(&b)))
}

// Drive the window directly so the tests don't depend on wall-clock timing.
// Spreads outcomes across enough distinct peers to clear the peer-diversity bar.
fn window_with(outcomes: &[(Timestamp, TransportSendOutcome)]) -> TransportWindow {
    let mut w = TransportWindow::default();
    for (i, (ts, o)) in outcomes.iter().enumerate() {
        w.record(*ts, *o, peer(i as u8));
    }
    w
}

pub fn test_verdict_needs_min_samples() {
    info!("--- test_verdict_needs_min_samples ---");

    // Below MIN_SAMPLES there is no verdict, however bad the evidence looks
    let outcomes: Vec<_> = (0..TRANSPORT_STATS_MIN_SAMPLES - 1)
        .map(|_| (now(), TransportSendOutcome::Timeout))
        .collect();
    let w = window_with(&outcomes);
    assert_eq!(w.verdict(now()), TransportVerdict::Unknown);

    // One more timeout crosses the threshold with no successes: suppressed
    let outcomes: Vec<_> = (0..TRANSPORT_STATS_MIN_SAMPLES)
        .map(|_| (now(), TransportSendOutcome::Timeout))
        .collect();
    let w = window_with(&outcomes);
    assert_eq!(
        w.verdict(now()),
        TransportVerdict::Suppressed {
            due_for_canary: false
        }
    );
}

pub fn test_verdict_any_success_is_healthy() {
    info!("--- test_verdict_any_success_is_healthy ---");

    // Strict suppression: a single success in the window keeps the transport usable,
    // so a merely lossy transport is never suppressed
    let mut outcomes: Vec<_> = (0..TRANSPORT_STATS_MIN_SAMPLES)
        .map(|_| (now(), TransportSendOutcome::Timeout))
        .collect();
    outcomes.push((now(), TransportSendOutcome::Sent));
    let w = window_with(&outcomes);
    assert_eq!(w.verdict(now()), TransportVerdict::Healthy);
}

pub fn test_window_keeps_min_samples_when_quiet() {
    info!("--- test_window_keeps_min_samples_when_quiet ---");

    // All outcomes are older than the window, but eviction stops at MIN_SAMPLES so a
    // quiet steady state still has a verdict instead of decaying to Unknown
    let outcomes: Vec<_> = (0..TRANSPORT_STATS_MIN_SAMPLES + 4)
        .map(|_| (secs_ago(60), TransportSendOutcome::Timeout))
        .collect();
    let mut w = window_with(&outcomes);
    w.evict_aged(now());
    assert_eq!(w.sample_count(), TRANSPORT_STATS_MIN_SAMPLES);
    assert!(matches!(
        w.verdict(now()),
        TransportVerdict::Suppressed { .. }
    ));
}

pub fn test_canary_becomes_due() {
    info!("--- test_canary_becomes_due ---");

    // Freshly suppressed: not yet due, so selection keeps avoiding this transport
    let outcomes: Vec<_> = (0..TRANSPORT_STATS_MIN_SAMPLES)
        .map(|_| (now(), TransportSendOutcome::Timeout))
        .collect();
    let w = window_with(&outcomes);
    assert!(w.verdict(now()).is_deprioritized());

    // Nothing attempted for longer than the canary interval: let one send through,
    // otherwise suppression would starve its own window and never recover
    let stale: Vec<_> = (0..TRANSPORT_STATS_MIN_SAMPLES)
        .map(|_| (secs_ago(120), TransportSendOutcome::Timeout))
        .collect();
    let w = window_with(&stale);
    assert_eq!(
        w.verdict(now()),
        TransportVerdict::Suppressed {
            due_for_canary: true
        }
    );
    assert!(!w.verdict(now()).is_deprioritized());
}

pub fn test_concentrated_failures_are_not_a_dead_path() {
    info!("--- test_concentrated_failures_are_not_a_dead_path ---");

    // A pile of failures against ONE peer means that peer's dial info is stale,
    // not that our path is broken, so there must be no verdict
    let mut w = TransportWindow::default();
    for _ in 0..TRANSPORT_STATS_MIN_SAMPLES * 2 {
        w.record(now(), TransportSendOutcome::Timeout, peer(1));
    }
    assert_eq!(w.verdict(now()), TransportVerdict::Unknown);

    // The same failures spread across enough distinct peers do implicate the path
    let mut w = TransportWindow::default();
    for i in 0..TRANSPORT_STATS_MIN_SAMPLES {
        w.record(now(), TransportSendOutcome::Timeout, peer(i as u8));
    }
    assert!(matches!(
        w.verdict(now()),
        TransportVerdict::Suppressed { .. }
    ));
}

pub fn test_skipping_does_not_defer_the_canary() {
    info!("--- test_skipping_does_not_defer_the_canary ---");

    // Skips must not push last_attempt_ts, or a busy suppressed transport would
    // starve its own canary
    let outcomes: Vec<_> = (0..TRANSPORT_STATS_MIN_SAMPLES)
        .map(|_| (secs_ago(120), TransportSendOutcome::Timeout))
        .collect();
    let w = window_with(&outcomes);
    let before = w.sample_count();
    assert_eq!(
        w.verdict(now()),
        TransportVerdict::Suppressed {
            due_for_canary: true
        }
    );
    assert_eq!(w.sample_count(), before);
}

pub fn test_suppression_survives_losing_peer_diversity() {
    info!("--- test_suppression_survives_losing_peer_diversity ---");

    // Window decay bunches survivors onto few peers; re-testing the entry bar
    // there would un-suppress on thin evidence and oscillate
    let mut w = TransportWindow::default();
    for i in 0..TRANSPORT_STATS_MIN_SAMPLES {
        w.record(secs_ago(60), TransportSendOutcome::Timeout, peer(i as u8));
    }
    assert!(matches!(
        w.verdict(secs_ago(60)),
        TransportVerdict::Suppressed { .. }
    ));

    // The canary trickles retries at one peer while the spread evidence ages out,
    // leaving only the concentrated survivors
    for _ in 0..TRANSPORT_STATS_MIN_SAMPLES {
        w.record(now(), TransportSendOutcome::Timeout, peer(1));
    }
    w.evict_aged(now());
    assert!(w.distinct_peers() < TRANSPORT_STATS_MIN_DISTINCT_PEERS);
    assert!(matches!(
        w.verdict(now()),
        TransportVerdict::Suppressed { .. }
    ));

    // Only a send that works releases it
    w.record(now(), TransportSendOutcome::Sent, peer(1));
    assert_eq!(w.verdict(now()), TransportVerdict::Healthy);
}

pub fn test_unbound_sends_count_toward_diversity() {
    info!("--- test_unbound_sends_count_toward_diversity ---");

    // Bootstrap and dial info discovery have no node behind them, but they are real
    // evidence about our own path, so distinct addresses must satisfy the same bar
    fn addr(n: u8) -> TransportPeerKey {
        TransportPeerKey::Address(SocketAddress::new(
            Address::IPV4(std::net::Ipv4Addr::new(10, 0, 0, n)),
            5150,
        ))
    }

    let mut w = TransportWindow::default();
    for i in 0..TRANSPORT_STATS_MIN_SAMPLES {
        w.record(now(), TransportSendOutcome::Timeout, addr(i as u8));
    }
    assert!(matches!(
        w.verdict(now()),
        TransportVerdict::Suppressed { .. }
    ));

    // Repeats against one address are one endpoint, exactly as for one node
    let mut w = TransportWindow::default();
    for _ in 0..TRANSPORT_STATS_MIN_SAMPLES * 2 {
        w.record(now(), TransportSendOutcome::Timeout, addr(1));
    }
    assert_eq!(w.verdict(now()), TransportVerdict::Unknown);
}

pub fn test_all() {
    test_verdict_needs_min_samples();
    test_verdict_any_success_is_healthy();
    test_window_keeps_min_samples_when_quiet();
    test_canary_becomes_due();
    test_concentrated_failures_are_not_a_dead_path();
    test_skipping_does_not_defer_the_canary();
    test_suppression_survives_losing_peer_diversity();
    test_unbound_sends_count_toward_diversity();
}
