use super::*;

/// Resources that need cleanup when a transaction is dropped
#[must_use]
pub(in crate::storage_manager) struct TransactionCleanup {
    /// The transaction handle being cleaned up
    pub transaction_handle: OutboundTransactionHandle,
    /// Background tokens to wait on
    pub background_tokens: Vec<StopToken>,
    /// Safety routes to unlock
    pub locked_safety_routes: LockedSafetyRoutes,
}

impl TransactionCleanup {
    pub fn merge(&mut self, other: Self) {
        self.background_tokens.extend(other.background_tokens);
        self.locked_safety_routes.merge(other.locked_safety_routes);
    }
}
