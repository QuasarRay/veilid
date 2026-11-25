//! The storage budget: per-filesystem and total budgets, equal shares, borrowing and the
//! minimum, for every layout of shared stores over filesystems.

use super::*;
use crate::storage_manager::storage_budget::*;

const GIB: u64 = 1024 * MIB;

fn limits(percent: Option<u32>, total: Option<u64>, minimum: u64) -> StorageBudgetLimits {
    StorageBudgetLimits {
        percent,
        total,
        minimum,
    }
}

fn pool(id: u64, available: u64) -> StoragePool {
    StoragePool { id, available }
}

fn store(pool: u64, used: u64) -> BudgetedStore {
    BudgetedStore { pool, used }
}

/// Both limits on one filesystem: the smaller budget wins.
fn test_one_store_both_limits() {
    let caps = storage_budget_caps(
        &limits(Some(25), Some(10 * GIB), 0),
        &[pool(1, 100 * GIB)],
        &[store(1, 0)],
    );
    assert_eq!(caps, vec![Some(10 * GIB)]);

    let caps = storage_budget_caps(
        &limits(Some(25), Some(10 * GIB), 0),
        &[pool(1, 20 * GIB)],
        &[store(1, 0)],
    );
    assert_eq!(caps, vec![Some(5 * GIB)]);
}

/// The store's own use counts in its pool, so growing never shrinks its budget.
fn test_own_use_is_in_the_pool() {
    let empty = storage_budget_caps(
        &limits(Some(25), None, 0),
        &[pool(1, 40 * GIB)],
        &[store(1, 0)],
    );
    let half_full = storage_budget_caps(
        &limits(Some(25), None, 0),
        &[pool(1, 30 * GIB)],
        &[store(1, 10 * GIB)],
    );
    assert_eq!(empty, vec![Some(10 * GIB)]);
    assert_eq!(half_full, empty);
}

/// The MiB limit alone, with no pool measured.
fn test_total_only() {
    let caps = storage_budget_caps(&limits(None, Some(128 * MIB), 0), &[], &[store(0, 0)]);
    assert_eq!(caps, vec![Some(128 * MIB)]);
}

/// The percent limit alone, with the store's pool unmeasured: nothing covers it.
fn test_no_budget() {
    let caps = storage_budget_caps(&limits(Some(25), None, 0), &[], &[store(0, 0)]);
    assert_eq!(caps, vec![None]);
}

/// Two stores on one filesystem: each may always grow to half and borrows what the other leaves.
fn test_two_stores_one_filesystem() {
    let l = limits(Some(25), None, 0);

    // Both empty: either may take the whole budget
    let caps = storage_budget_caps(&l, &[pool(1, 80 * GIB)], &[store(1, 0), store(1, 0)]);
    assert_eq!(caps, vec![Some(20 * GIB), Some(20 * GIB)]);

    // One holds 15 of the 23.75 GiB budget: it may borrow on, the other keeps its half
    let caps = storage_budget_caps(&l, &[pool(1, 80 * GIB)], &[store(1, 15 * GIB), store(1, 0)]);
    assert_eq!(caps, vec![Some(24320 * MIB), Some(12160 * MIB)]);

    // One borrowed past its half: it stops at the budget less the other's use, and the other
    // still gets its half
    let caps = storage_budget_caps(
        &l,
        &[pool(1, 64 * GIB)],
        &[store(1, 4 * GIB), store(1, 12 * GIB)],
    );
    assert_eq!(caps, vec![Some(10 * GIB), Some(16 * GIB)]);
}

/// Two stores on two filesystems: separate percent budgets, coupled only by the total.
fn test_two_stores_two_filesystems() {
    let pools = [pool(1, 100 * GIB), pool(2, 20 * GIB)];

    let caps = storage_budget_caps(
        &limits(Some(25), None, 0),
        &pools,
        &[store(1, 0), store(2, 0)],
    );
    assert_eq!(caps, vec![Some(25 * GIB), Some(5 * GIB)]);

    let caps = storage_budget_caps(
        &limits(Some(25), Some(10 * GIB), 0),
        &pools,
        &[store(1, 0), store(2, 4 * GIB)],
    );
    assert_eq!(
        caps,
        vec![Some(6 * GIB), Some(6 * GIB)],
        "each borrows what the other leaves of the total, within its own filesystem's budget"
    );
}

/// The base directory's filesystem holds no shared store, so it sets no budget.
fn test_base_directory_on_another_filesystem() {
    let caps = storage_budget_caps(
        &limits(Some(25), None, 0),
        &[pool(3, 1000 * GIB), pool(1, 40 * GIB)],
        &[store(1, 0)],
    );
    assert_eq!(caps, vec![Some(10 * GIB)]);
}

/// The minimum holds even when the budget is smaller.
fn test_minimum() {
    let caps = storage_budget_caps(
        &limits(Some(25), None, 64 * MIB),
        &[pool(1, 100 * MIB)],
        &[store(1, 0)],
    );
    assert_eq!(caps, vec![Some(64 * MIB)]);

    let caps = storage_budget_caps(
        &limits(Some(25), None, 64 * MIB),
        &[pool(1, 100 * GIB)],
        &[store(1, 0)],
    );
    assert_eq!(
        caps,
        vec![Some(25 * GIB)],
        "a larger budget is not capped by the minimum"
    );
}

/// Setting one limit drops the other's default; with neither set both defaults apply.
fn test_limits_from_config() {
    let mut storage = VeilidConfigStorage::default();
    let defaults = StorageBudgetLimits::from_config(&storage, true);
    assert_eq!(defaults.percent, Some(25));
    assert!(defaults.total.is_some());
    assert_eq!(defaults.minimum, 0);

    storage.limit_percent = Some(10);
    let percent_only = StorageBudgetLimits::from_config(&storage, true);
    assert_eq!((percent_only.percent, percent_only.total), (Some(10), None));

    // No pool to take a percent of: the MiB limit's default applies
    let unmeasured = StorageBudgetLimits::from_config(&storage, false);
    assert_eq!(unmeasured.percent, Some(10));
    assert_eq!(unmeasured.total, defaults.total);

    storage.limit_percent = None;
    storage.limit_mb = Some(512);
    let mb_only = StorageBudgetLimits::from_config(&storage, true);
    assert_eq!((mb_only.percent, mb_only.total), (None, Some(512 * MIB)));

    storage.limit_percent = Some(50);
    storage.minimum_mb = 16;
    let both = StorageBudgetLimits::from_config(&storage, true);
    assert_eq!(
        (both.percent, both.total, both.minimum),
        (Some(50), Some(512 * MIB), 16 * MIB)
    );
}

/// The record index limit scales the cap by how many counted bytes each byte on disk holds.
fn test_counted_limit() {
    let measured = |live, counted| MeasuredStore {
        pool: 1,
        used: live,
        live,
        counted,
    };
    assert_eq!(
        measured(0, 0).counted_limit(GIB),
        GIB,
        "an empty store counts 1:1"
    );
    assert_eq!(measured(2 * GIB, GIB).counted_limit(10 * GIB), 5 * GIB);
    assert_eq!(measured(GIB, 2 * GIB).counted_limit(10 * GIB), 20 * GIB);
}

pub fn test_all() {
    test_one_store_both_limits();
    test_own_use_is_in_the_pool();
    test_total_only();
    test_no_budget();
    test_two_stores_one_filesystem();
    test_two_stores_two_filesystems();
    test_base_directory_on_another_filesystem();
    test_minimum();
    test_limits_from_config();
    test_counted_limit();
}
