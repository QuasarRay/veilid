use crate::*;

const EARLY_TOLERANCE_US: u64 = 20_000;

fn assert_not_early(deadline: u64, what: &str) {
    assert!(
        get_raw_timestamp() + EARLY_TOLERANCE_US >= deadline,
        "{what} completed more than {EARLY_TOLERANCE_US}us before its deadline"
    );
}

pub async fn test_fires_at_its_deadline() {
    let deadline = get_raw_timestamp() + 200_000;

    timeout(5_000, sleep_until(deadline))
        .await
        .expect("the sleep should complete well inside the timeout");

    assert_not_early(deadline, "the sleep");
}

pub async fn test_reset_to_a_later_deadline_delays_it() {
    let start = get_raw_timestamp();
    let mut timer = sleep_until(start + 100_000);

    let deadline = start + 500_000;
    timer.reset(deadline);

    timeout(5_000, timer)
        .await
        .expect("the later deadline should still complete inside the timeout");

    assert_not_early(deadline, "the delayed sleep");
}

pub async fn test_reset_to_an_earlier_deadline_advances_it() {
    let start = get_raw_timestamp();
    let mut timer = sleep_until(start + 10_000_000);

    let deadline = start + 200_000;
    timer.reset(deadline);

    timeout(3_000, timer)
        .await
        .expect("the earlier deadline should fire long before the original one");

    assert_not_early(deadline, "the advanced sleep");
}

pub async fn test_reset_after_a_poll_still_wakes() {
    let start = get_raw_timestamp();
    let mut timer = sleep_until(start + 10_000_000);

    let first = std::future::poll_fn(|cx| task::Poll::Ready(Pin::new(&mut timer).poll(cx))).await;
    assert!(
        first.is_pending(),
        "a sleep ten seconds out must not be ready on its first poll"
    );

    let deadline = start + 250_000;
    timer.reset(deadline);

    timeout(3_000, timer)
        .await
        .expect("the reset deadline should wake the task that already polled the sleep");

    assert_not_early(deadline, "the sleep reset after a poll");
}

pub async fn test_all() {
    test_fires_at_its_deadline().await;
    test_reset_to_a_later_deadline_delays_it().await;
    test_reset_to_an_earlier_deadline_advances_it().await;
    test_reset_after_a_poll_still_wakes().await;
}
