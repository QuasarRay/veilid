use crate::routing_table::*;

fn now() -> Timestamp {
    Timestamp::new(1_000_000_000u64)
}

fn only(ordering: SequenceOrdering) -> SequenceOrderingSet {
    SequenceOrderingSet::only(ordering)
}

pub fn test_loopback_failure_run_kills_ordering() {
    info!("--- test_loopback_failure_run_kills_ordering ---");
    let mut stats = RouteStats::new(now());
    let threshold = loopback_failure_threshold(SequenceOrdering::Unordered);

    for n in 1..threshold {
        let tally = stats.record_loopback_result(SequenceOrdering::Unordered, false, now());
        assert_eq!(tally.streak, n);
        assert!(!stats.is_dead_for_ordering(SequenceOrdering::Unordered));
        // A failing ordering wants a retest
        assert!(stats.needs_testing(only(SequenceOrdering::Unordered), now()));
    }
    let tally = stats.record_loopback_result(SequenceOrdering::Unordered, false, now());
    assert_eq!(tally.fail, threshold as u64);
    assert!(stats.is_dead_for_ordering(SequenceOrdering::Unordered));
    assert!(stats.is_dead_for(only(SequenceOrdering::Unordered)));

    // The other ordering is untouched and never counted
    assert!(!stats.is_dead_for_ordering(SequenceOrdering::Ordered));
    assert!(!stats.is_dead_for(only(SequenceOrdering::Ordered)));
}

pub fn test_loopback_pass_resets_run() {
    info!("--- test_loopback_pass_resets_run ---");
    let mut stats = RouteStats::new(now());
    let threshold = loopback_failure_threshold(SequenceOrdering::Ordered);

    for _ in 1..threshold {
        stats.record_loopback_result(SequenceOrdering::Ordered, false, now());
    }
    let tally = stats.record_loopback_result(SequenceOrdering::Ordered, true, now());
    // The pass reports the run it ended
    assert_eq!(tally.streak, threshold - 1);
    assert_eq!(tally.pass, 1);
    assert!(!stats.is_dead_for_ordering(SequenceOrdering::Ordered));
    assert!(!stats.needs_testing(only(SequenceOrdering::Ordered), now()));

    // A fresh run starts from zero
    let tally = stats.record_loopback_result(SequenceOrdering::Ordered, false, now());
    assert_eq!(tally.streak, 1);
    assert!(!stats.is_dead_for_ordering(SequenceOrdering::Ordered));
}

pub fn test_send_does_not_clear_loopback_run() {
    info!("--- test_send_does_not_clear_loopback_run ---");
    let mut stats = RouteStats::new(now());
    let threshold = loopback_failure_threshold(SequenceOrdering::Ordered);

    for _ in 1..threshold {
        stats.record_loopback_result(SequenceOrdering::Ordered, false, now());
        // Sending over the route is not evidence it works
        stats.record_sent(SequenceOrdering::Ordered, now(), ByteCount::new(100));
    }
    stats.record_loopback_result(SequenceOrdering::Ordered, false, now());
    assert!(stats.is_dead_for_ordering(SequenceOrdering::Ordered));
}

pub fn test_send_failure_does_not_kill_the_route() {
    info!("--- test_send_failure_does_not_kill_the_route ---");
    // A send failure names us and the first hop, not the route
    let mut stats = RouteStats::new(now());
    stats.record_send_failed(SequenceOrdering::Ordered);
    assert!(!stats.is_dead_for(only(SequenceOrdering::Ordered)));
    assert!(!stats.death_blames_hops_for(only(SequenceOrdering::Ordered)));
    // but it is still a reason to recompile and retest
    assert!(stats
        .ordering_disposition(SequenceOrdering::Ordered)
        .needs_recompile());
    assert!(stats.needs_testing(only(SequenceOrdering::Ordered), now()));

    // A send failure must not pre-empt the loopback threshold
    let mut stats = RouteStats::new(now());
    stats.record_send_failed(SequenceOrdering::Ordered);
    stats.record_loopback_result(SequenceOrdering::Ordered, false, now());
    assert!(
        !stats.is_dead_for(only(SequenceOrdering::Ordered)),
        "one bad loopback is not a dead route, whether or not a send failed"
    );

    // Evidence spanning the route kills it, and blames the hops
    let mut stats = RouteStats::new(now());
    for _ in 0..loopback_failure_threshold(SequenceOrdering::Ordered) {
        stats.record_loopback_result(SequenceOrdering::Ordered, false, now());
    }
    assert!(stats.is_dead_for(only(SequenceOrdering::Ordered)));
    assert!(stats.death_blames_hops_for(only(SequenceOrdering::Ordered)));
    assert!(!stats.death_blames_hops_for(only(SequenceOrdering::Unordered)));
}

pub fn test_sequencing_narrows_to_route_orderings() {
    info!("--- test_sequencing_narrows_to_route_orderings ---");
    let ordered = only(SequenceOrdering::Ordered);
    let unordered = only(SequenceOrdering::Unordered);

    assert_eq!(
        Sequencing::PreferUnordered.for_route_orderings(ordered),
        Sequencing::PreferOrdered
    );
    assert_eq!(
        Sequencing::PreferUnordered.for_route_orderings(unordered),
        Sequencing::PreferUnordered
    );
    assert_eq!(
        Sequencing::PreferOrdered.for_route_orderings(unordered),
        Sequencing::PreferOrdered
    );
    assert_eq!(
        Sequencing::EnsureOrdered.for_route_orderings(unordered),
        Sequencing::EnsureOrdered
    );

    assert_eq!(
        Sequencing::PreferUnordered.preferred_ordering(),
        SequenceOrdering::Unordered
    );
    assert_eq!(
        Sequencing::PreferOrdered.preferred_ordering(),
        SequenceOrdering::Ordered
    );
    assert_eq!(
        Sequencing::EnsureOrdered.preferred_ordering(),
        SequenceOrdering::Ordered
    );
}

pub fn test_all() {
    test_send_failure_does_not_kill_the_route();
    test_loopback_failure_run_kills_ordering();
    test_loopback_pass_resets_run();
    test_send_does_not_clear_loopback_run();
    test_sequencing_narrows_to_route_orderings();
}
