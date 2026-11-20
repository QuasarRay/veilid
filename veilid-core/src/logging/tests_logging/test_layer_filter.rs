use super::test_log_throttle::CountingLayer;
use super::*;
use tracing_subscriber::prelude::*;

/// A name ending in `*` tags every target under that prefix, and nothing else
pub fn test_add_facilities_prefix() {
    VeilidLayerFilter::add_facilities(
        [],
        ["prefix_test_app", "prefix_test_app::*"],
        ["#prefix_test"],
    )
    .expect("should add facilities");
    let filter = VeilidLayerFilter::new_with_config(
        VeilidLayerFilterConfig::new()
            .try_with_directives_string("#prefix_test=info")
            .expect("valid directives"),
    );
    let count = Arc::new(AtomicUsize::new(0));
    let subscriber =
        tracing_subscriber::registry().with(CountingLayer(Arc::clone(&count)).with_filter(filter));

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: "prefix_test_app", "crate root");
        tracing::info!(target: "prefix_test_app::module", "module");
        tracing::info!(target: "prefix_test_application", "another crate");
        tracing::debug!(target: "prefix_test_app::module", "below the level");
    });
    assert_eq!(count.load(Ordering::Relaxed), 2);

    assert!(
        VeilidLayerFilter::add_facilities([], ["*"], ["#prefix_test"]).is_err(),
        "a bare '*'"
    );
    assert!(
        VeilidLayerFilter::add_facilities([], ["prefix*test"], ["#prefix_test"]).is_err(),
        "a '*' before the end"
    );
}

pub fn test_all() {
    test_add_facilities_prefix();
}
