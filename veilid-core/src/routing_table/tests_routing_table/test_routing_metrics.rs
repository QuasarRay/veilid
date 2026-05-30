use crate::routing_table::*;

pub fn test_bucket_depth() {
    info!("--- test_bucket_depth ---");

    assert_eq!(RoutingTable::bucket_depth(0), 256);
    assert_eq!(RoutingTable::bucket_depth(1), 128);
    assert_eq!(RoutingTable::bucket_depth(2), 64);
    assert_eq!(RoutingTable::bucket_depth(3), 32);
    assert_eq!(RoutingTable::bucket_depth(4), 16);
    assert_eq!(RoutingTable::bucket_depth(5), 8);
    assert_eq!(RoutingTable::bucket_depth(6), 4);
    assert_eq!(RoutingTable::bucket_depth(7), 2);
    assert_eq!(RoutingTable::bucket_depth(8), 1);
    assert_eq!(RoutingTable::bucket_depth(255), 1);
}

pub fn test_practical_max_size_zero() {
    info!("--- test_practical_max_size_zero ---");

    assert_eq!(
        RoutingTable::practical_max_size(NodeCount::from(0)),
        NodeCount::from(0)
    );
}

pub fn test_practical_max_size_small_network_holds_most_nodes() {
    info!("--- test_practical_max_size_small_network_holds_most_nodes ---");

    for n in [1u64, 10, 50, 100] {
        let got = RoutingTable::practical_max_size(NodeCount::from(n));
        assert!(got.as_u64() <= n, "expected <= n; n={n}, got={got}");
        assert!(
            got.as_u64() >= n.saturating_sub(8),
            "expected ~n for small n; n={n}, got={got}"
        );
    }
}

pub fn test_practical_max_size_known_values() {
    info!("--- test_practical_max_size_known_values ---");

    // Real DHTs never reach the 758-entry theoretical max; far-away buckets
    // stay sparse because nodes are random.
    assert_eq!(
        RoutingTable::practical_max_size(NodeCount::from(1_000)),
        NodeCount::from(511)
    );
    assert_eq!(
        RoutingTable::practical_max_size(NodeCount::from(10_000)),
        NodeCount::from(515)
    );
    assert_eq!(
        RoutingTable::practical_max_size(NodeCount::from(1_000_000)),
        NodeCount::from(521)
    );
    assert_eq!(
        RoutingTable::practical_max_size(NodeCount::from(u64::MAX)),
        NodeCount::from(565)
    );
}

pub fn test_practical_max_size_monotonic() {
    info!("--- test_practical_max_size_monotonic ---");

    let mut prev = NodeCount::from(0);
    for n in [0u64, 1, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096, 16384] {
        let got = RoutingTable::practical_max_size(NodeCount::from(n));
        assert!(
            got >= prev,
            "non-monotonic at n={n}: prev={prev}, got={got}"
        );
        prev = got;
    }
}
