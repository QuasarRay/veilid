use super::*;

/// One node's watch on a record.
#[derive(Clone)]
pub(crate) struct MockWatch {
    pub watcher: MockNodeKey,
    pub subkeys: ValueSubkeyRangeSet,
    pub count: u32,
    /// When the watch lapses, or zero for a watch that was never given a deadline
    pub expiration: Timestamp,
}

impl MockWatch {
    fn expired(&self, now: Timestamp) -> bool {
        self.expiration.as_u64() != 0 && now > self.expiration
    }
}

/// A change to deliver once the record lock is released.
struct PendingChange {
    watcher: MockNodeKey,
    change: VeilidValueChange,
}

impl VeilidAPI {
    /// Register or replace this node's watch on a record.
    pub(crate) fn mock_watch_dht_values(
        &self,
        record_key: RecordKey,
        subkeys: Option<ValueSubkeyRangeSet>,
        expiration: Option<Timestamp>,
        count: Option<u32>,
    ) -> VeilidAPIResult<bool> {
        let key = self.mock_key()?;
        let count = count.unwrap_or(u32::MAX);
        // An empty range means the whole record, as it does on the real path
        let subkeys = subkeys.unwrap_or_default();

        with_records(|records| {
            let record = records
                .get_mut(&record_key.opaque())
                .ok_or_else(|| VeilidAPIError::key_not_found(record_key.opaque()))?;

            let subkeys = if subkeys.is_empty() {
                ValueSubkeyRangeSet::full()
            } else {
                subkeys
            };
            let subkeys = record.schema.truncate_subkeys(&subkeys, None);

            record.watches.retain(|w| w.watcher != key);
            if count == 0 {
                // A zero count cancels rather than registers
                return VeilidAPIResult::Ok(false);
            }
            record.watches.push(MockWatch {
                watcher: key,
                subkeys,
                count,
                expiration: expiration.unwrap_or_else(|| Timestamp::new(0)),
            });
            VeilidAPIResult::Ok(true)
        })
    }

    /// Drop subkeys from this node's watch, cancelling it when nothing is left.
    pub(crate) fn mock_cancel_dht_watch(
        &self,
        record_key: RecordKey,
        subkeys: Option<ValueSubkeyRangeSet>,
    ) -> VeilidAPIResult<bool> {
        let key = self.mock_key()?;
        let subkeys = subkeys.unwrap_or_default();

        let (still_watching, was_watching) = with_records(|records| {
            let record = records
                .get_mut(&record_key.opaque())
                .ok_or_else(|| VeilidAPIError::key_not_found(record_key.opaque()))?;

            let Some(watch) = record.watches.iter_mut().find(|w| w.watcher == key) else {
                return VeilidAPIResult::Ok((false, false));
            };
            // An empty range cancels the whole watch
            if !subkeys.is_empty() {
                watch.subkeys = watch.subkeys.difference(&subkeys);
            } else {
                watch.subkeys = ValueSubkeyRangeSet::new();
            }
            let still_watching = !watch.subkeys.is_empty();
            if !still_watching {
                record.watches.retain(|w| w.watcher != key);
            }
            VeilidAPIResult::Ok((still_watching, true))
        })?;

        // A cancelled watch reports its own death, the same signal an expired watch gives
        if was_watching && !still_watching {
            let _ = MockNetwork::send_update(
                &key,
                VeilidUpdate::ValueChange(Box::new(VeilidValueChange {
                    key: record_key,
                    subkeys: ValueSubkeyRangeSet::new(),
                    count: 0,
                    value: None,
                })),
            );
        }
        Ok(still_watching)
    }
}

/// Note a committed change and hand back the reports to deliver.
///
/// Runs under the record lock and sends nothing itself, so that delivery happens with no lock held.
fn take_changes(
    records: &mut HashMap<OpaqueRecordKey, MockRecord>,
    record_key: &RecordKey,
    writer: MockNodeKey,
    changed: &ValueSubkeyRangeSet,
) -> Vec<PendingChange> {
    let Some(record) = records.get_mut(&record_key.opaque()) else {
        return Vec::new();
    };

    // Nothing sweeps expired watches, so they lapse on the next change instead
    let now = Timestamp::now();
    let lapsed: Vec<MockNodeKey> = record
        .watches
        .iter()
        .filter(|w| w.expired(now))
        .map(|w| w.watcher)
        .collect();
    record.watches.retain(|w| !w.expired(now));

    let mut pending = Vec::new();
    for watch in &mut record.watches {
        // The writer does not hear its own change, matching ExcludeTarget on the real path
        if watch.watcher == writer {
            continue;
        }
        let reportable = watch.subkeys.intersect(changed);
        if reportable.is_empty() {
            continue;
        }

        watch.count = watch.count.saturating_sub(1);

        // A single changed subkey carries its value; a wider range is a hint to go read
        let value = if reportable.len() == 1 {
            reportable
                .first()
                .and_then(|sk| record.subkeys.get(&sk))
                .cloned()
        } else {
            None
        };

        pending.push(PendingChange {
            watcher: watch.watcher,
            change: VeilidValueChange {
                key: record_key.clone(),
                subkeys: reportable,
                count: watch.count,
                value,
            },
        });
    }

    // A dead watch is reported to its holder with an empty range and zero count
    let mut dead: Vec<MockNodeKey> = record
        .watches
        .iter()
        .filter(|w| w.count == 0)
        .map(|w| w.watcher)
        .collect();
    dead.extend(lapsed);
    for watcher in dead {
        record.watches.retain(|w| w.watcher != watcher);
        pending.push(PendingChange {
            watcher,
            change: VeilidValueChange {
                key: record_key.clone(),
                subkeys: ValueSubkeyRangeSet::new(),
                count: 0,
                value: None,
            },
        });
    }
    pending
}

/// Report a committed change to every watcher but the writer.
pub(crate) fn report_value_change(
    record_key: &RecordKey,
    writer: MockNodeKey,
    changed: &ValueSubkeyRangeSet,
) {
    let pending = with_records(|records| take_changes(records, record_key, writer, changed));

    // Delivered outside the record lock: a callback may re-enter the API
    for p in pending {
        let _ = MockNetwork::send_update(&p.watcher, VeilidUpdate::ValueChange(Box::new(p.change)));
    }
}
