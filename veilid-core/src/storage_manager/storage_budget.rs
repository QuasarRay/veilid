//! Disk budget for the stores that hold data for other nodes
//!
//! - A pool is a filesystem, or the browser origin: its free space plus what the shared stores
//!   already take there, so a store's own growth never shrinks its budget
//! - The budgets are `storage.limit_percent` of each pool and `storage.limit_mb` across pools
//! - Each shared store may always grow to an equal share of every budget it draws on, or to
//!   `storage.minimum_mb` if larger, and may borrow what the other stores leave unused
//! - Table files never shrink (freed pages are reused), so a limit stops growth: a store over its
//!   limit keeps its records and replaces the least recently used ones
//! - Without a pool measurement (an insecure browser context) only the MiB limit applies

use super::*;

pub(super) const MIB: u64 = 1_048_576;

/// Identifies a pool: a filesystem, or the browser origin
pub(super) type StoragePoolId = u64;

/// A pool's free space
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StoragePool {
    /// Which pool
    pub id: StoragePoolId,
    /// Bytes still free there
    pub available: u64,
}

/// A shared store's pool and what it takes there
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BudgetedStore {
    /// Pool holding the store's files
    pub pool: StoragePoolId,
    /// Bytes the store takes from its pool
    pub used: u64,
}

/// The storage limits in force
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StorageBudgetLimits {
    /// Share of each pool, in percent
    pub percent: Option<u32>,
    /// Bytes across all pools
    pub total: Option<u64>,
    /// Bytes each store may always grow to
    pub minimum: u64,
}

impl StorageBudgetLimits {
    /// The limits `storage` sets; with no pool measured, the MiB limit or its default
    pub fn from_config(storage: &VeilidConfigStorage, pool_measured: bool) -> Self {
        let (percent, mut total_mb) = storage.effective_limits();
        if !pool_measured && total_mb.is_none() {
            total_mb = Some(default_storage_limit_mb());
        }
        Self {
            percent,
            total: total_mb.map(|mb| u64::from(mb) * MIB),
            minimum: u64::from(storage.minimum_mb) * MIB,
        }
    }
}

fn percent_of(bytes: u64, percent: u32) -> u64 {
    u64::try_from(u128::from(bytes) * u128::from(percent) / 100).unwrap_or(u64::MAX)
}

fn sum_used<'a>(stores: impl Iterator<Item = &'a BudgetedStore>) -> u64 {
    stores.fold(0u64, |acc, s| acc.saturating_add(s.used))
}

/// Bytes each store may take from its pool, in order: its share of every budget it is in (or the
/// minimum), raised to what the other stores leave unused. None when no budget covers the store.
pub(super) fn storage_budget_caps(
    limits: &StorageBudgetLimits,
    pools: &[StoragePool],
    stores: &[BudgetedStore],
) -> Vec<Option<u64>> {
    let pool_budget = |pool: StoragePoolId| -> Option<u64> {
        let percent = limits.percent?;
        let available = pools.iter().find(|p| p.id == pool)?.available;
        let used = sum_used(stores.iter().filter(|s| s.pool == pool));
        Some(percent_of(available.saturating_add(used), percent))
    };

    stores
        .iter()
        .enumerate()
        .map(|(n, store)| {
            // Each budget this store draws on, with the stores that share it
            let mut budgets: Vec<(u64, Vec<usize>)> = Vec::new();
            if let Some(budget) = pool_budget(store.pool) {
                let members = (0..stores.len())
                    .filter(|&m| stores[m].pool == store.pool)
                    .collect();
                budgets.push((budget, members));
            }
            if let Some(total) = limits.total {
                budgets.push((total, (0..stores.len()).collect()));
            }

            let share = budgets
                .iter()
                .map(|(budget, members)| budget / members.len() as u64)
                .min()?;
            let borrowable = budgets
                .iter()
                .map(|(budget, members)| {
                    let others = sum_used(members.iter().filter(|&&m| m != n).map(|&m| &stores[m]));
                    budget.saturating_sub(others)
                })
                .min()?;
            Some(share.max(limits.minimum).max(borrowable))
        })
        .collect()
}

/// A record store's limit and use on one measurement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StoreLimitReport {
    /// Bytes of data the store holds
    pub data: u64,
    /// Bytes of data the store may hold; None = unlimited
    pub limit: Option<u64>,
    /// Whether the limit is a share of the storage budget
    pub shared: bool,
    /// Whether the budget measured its pool's free space
    pub pool_measured: bool,
}

impl fmt::Display for StoreLimitReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let limit = self
            .limit
            .map_or_else(|| "unlimited".to_owned(), human_byte_count);
        write!(f, "{}/{}", human_byte_count(self.data), limit)?;
        match (self.limit, self.shared) {
            (Some(_), true) => write!(f, " (shared)"),
            (Some(_), false) => write!(f, " (fixed)"),
            (None, _) => Ok(()),
        }
    }
}

/// A shared store as measured now
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MeasuredStore {
    /// Pool holding its files
    pub pool: StoragePoolId,
    /// Bytes it takes from the pool, free pages in its files included
    pub used: u64,
    /// Bytes in the pages that hold its data
    pub live: u64,
    /// Bytes its record index counts toward its limit
    pub counted: u64,
}

impl MeasuredStore {
    /// The record index limit that keeps the store's data within `cap` bytes
    pub fn counted_limit(&self, cap: u64) -> u64 {
        if self.live == 0 || self.counted == 0 {
            return cap;
        }
        u64::try_from(u128::from(cap) * u128::from(self.counted) / u128::from(self.live))
            .unwrap_or(u64::MAX)
    }
}

impl StorageManager {
    /// Set the remote record store's limit from the config and what it and its pool hold now
    pub(super) async fn update_storage_limits(&self) -> VeilidAPIResult<StoreLimitReport> {
        let config = self.config();
        let remote_record_store = self.get_remote_record_store()?;

        let fixed_mb = config.network.dht.remote_max_storage_space_mb;
        if fixed_mb != 0 {
            let limit = u64::from(fixed_mb) * MIB;
            remote_record_store.set_storage_limit(Some(limit));
            return Ok(StoreLimitReport {
                data: remote_record_store.total_storage_space(),
                limit: Some(limit),
                shared: false,
                pool_measured: false,
            });
        }

        let (store, pool) = self.measure_record_store(&remote_record_store).await?;
        let pool_measured = pool.is_some();
        let limits = StorageBudgetLimits::from_config(&config.storage, pool_measured);
        let pools: Vec<StoragePool> = pool.into_iter().collect();
        let cap = storage_budget_caps(
            &limits,
            &pools,
            &[BudgetedStore {
                pool: store.pool,
                used: store.used,
            }],
        )[0];
        remote_record_store.set_storage_limit(cap.map(|cap| store.counted_limit(cap)));

        Ok(StoreLimitReport {
            data: store.live,
            limit: cap,
            shared: true,
            pool_measured,
        })
    }

    /// The store's use and the free space of its pool, when that can be measured
    async fn measure_record_store<D: RecordDetail>(
        &self,
        record_store: &RecordStore<D>,
    ) -> VeilidAPIResult<(MeasuredStore, Option<StoragePool>)> {
        let counted = record_store.total_storage_space();
        let usage = record_store
            .storage_usage()
            .await?
            .unwrap_or(TableStorageUsage {
                file_bytes: counted,
                live_bytes: counted,
            });
        let pool = self.measure_pool().await;
        let store = MeasuredStore {
            pool: pool.map(|p| p.id).unwrap_or_default(),
            used: usage.file_bytes,
            live: usage.live_bytes,
            counted,
        };
        Ok((store, pool))
    }

    /// Free space where the table store keeps its files
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[expect(clippy::unused_async)]
    async fn measure_pool(&self) -> Option<StoragePool> {
        let mut directory = self.config().table_store_directory();
        if directory.is_empty() {
            ".".clone_into(&mut directory);
        }
        match filesystem_space(&directory) {
            Ok(space) => {
                self.storage_pool_unmeasured.store(false, Ordering::Release);
                Some(StoragePool {
                    id: space.id,
                    available: space.available,
                })
            }
            Err(e) => {
                if !self.storage_pool_unmeasured.swap(true, Ordering::AcqRel) {
                    veilid_log!(self warn "Unable to measure free space at '{}', only the storage MiB limit applies: {}", directory, e);
                }
                None
            }
        }
    }

    /// The browser's free quota for this origin; None in an insecure context
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    async fn measure_pool(&self) -> Option<StoragePool> {
        use js_sys::{Function, Promise, Reflect};
        use send_wrapper::SendWrapper;
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;

        // A JsFuture holds an Rc, and the tick futures must be Send
        SendWrapper::new(async {
            let navigator =
                Reflect::get(&js_sys::global(), &JsValue::from_str("navigator")).ok()?;
            let storage = Reflect::get(&navigator, &JsValue::from_str("storage")).ok()?;
            if !storage.is_object() {
                return None;
            }
            let estimate: Function = Reflect::get(&storage, &JsValue::from_str("estimate"))
                .ok()?
                .dyn_into()
                .ok()?;
            let promise: Promise = estimate.call0(&storage).ok()?.dyn_into().ok()?;
            let result = JsFuture::from(promise).await.ok()?;
            let quota = Reflect::get(&result, &JsValue::from_str("quota"))
                .ok()?
                .as_f64()?;
            let usage = Reflect::get(&result, &JsValue::from_str("usage"))
                .ok()?
                .as_f64()?;
            Some(StoragePool {
                id: 0,
                available: (quota - usage).max(0.0) as u64,
            })
        })
        .await
    }

    /// Log where the stores live and their limits, so the budget math is visible at startup
    pub(super) async fn log_storage_summary(&self, remote: StoreLimitReport) {
        let config = self.config();

        cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
                veilid_log!(self info "Storage: browser origin");
            } else {
                veilid_log!(self info "Storage: {}", config.storage.directory);
                veilid_log!(self info "Table Store: {}", config.table_store_directory());
                veilid_log!(self info "Protected Store: {}", config.protected_store_directory());
                #[cfg(feature = "unstable-blockstore")]
                veilid_log!(self info "Block Store: {}", config.block_store_directory());
            }
        }

        if remote.shared {
            let measured = remote.pool_measured;
            let limits = StorageBudgetLimits::from_config(&config.storage, measured);
            let percent = limits
                .percent
                .map_or_else(|| "no".to_owned(), |p| format!("{}%", p));
            let total = limits.total.map_or_else(
                || "no total".to_owned(),
                |total| format!("{} total", human_byte_count(total)),
            );
            let pool = if measured {
                ""
            } else {
                ", free space not measurable"
            };
            veilid_log!(self info "Storage Budget: {} of free space, {}, {} minimum per store{}",
                percent, total, human_byte_count(limits.minimum), pool);
        }

        if let Ok(local_record_store) = self.get_local_record_store() {
            let data = match local_record_store.storage_usage().await {
                Ok(Some(usage)) => usage.live_bytes,
                _ => local_record_store.total_storage_space(),
            };
            let local = StoreLimitReport {
                data,
                limit: None,
                shared: false,
                pool_measured: false,
            };
            veilid_log!(self info "Local Record Store: {}", local);
        }
        veilid_log!(self info "Remote Record Store: {}", remote);
    }
}
