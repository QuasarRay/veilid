use super::*;

/// Tracks locked safety routes with per-key lock counts for correct unlock semantics
#[derive(Debug, Default)]
#[must_use]
pub(in crate::storage_manager) struct LockedSafetyRoutes {
    lock_counts: HashMap<PublicKey, usize>,
}

impl LockedSafetyRoutes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: PublicKey) {
        *self.lock_counts.entry(key).or_insert(0) += 1;
    }

    pub fn merge(&mut self, other: Self) {
        for (key, count) in other.lock_counts {
            *self.lock_counts.entry(key).or_insert(0) += count;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lock_counts.is_empty()
    }

    pub fn into_iter(self) -> impl Iterator<Item = (PublicKey, usize)> {
        self.lock_counts.into_iter()
    }

    pub fn len(&self) -> usize {
        self.lock_counts.len()
    }
}
