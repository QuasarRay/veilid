use super::*;

/// Keeping track of how many entries we have of each type we care about
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct EntryCounts {
    /// The total number of entries
    pub total: usize,
    /// The number of live entries
    pub live: usize,
    /// The number of live entries that have been tested
    pub tested: usize,
}

impl EntryCounts {
    pub(in crate::routing_table) fn add_entry(&mut self, e: &BucketEntrySnapshot) {
        self.total += 1;
        if matches!(
            e.state,
            BucketEntryState::Reliable | BucketEntryState::Unreliable
        ) {
            self.live += 1;
            if e.is_tested() {
                self.tested += 1;
            }
        }
    }
}

impl fmt::Display for EntryCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[total={}, live={}, tested={}]",
            self.total, self.live, self.tested
        )
    }
}

/// Keeping track of how many entries we have of each type we care about per crypto kind
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct EntrySummaryDetail {
    /// A count of the entries in the routing domain per crypto kind with any capabilities
    pub any_capabilities: EntryCounts,
    /// A count of the entries in the routing domain per crypto kind with all CONNECTIVITY_CAPABILITIES
    pub connectivity_capabilities: EntryCounts,
    /// A count of the entries in the routing domain per crypto kind with all DISTANCE_METRIC_CAPABILITIES
    pub distance_metric_capabilities: EntryCounts,
}

impl EntrySummaryDetail {
    pub(in crate::routing_table) fn add_entry(
        &mut self,
        routing_domain: RoutingDomain,
        e: &BucketEntrySnapshot,
    ) {
        self.any_capabilities.add_entry(e);
        if e.has_all_capabilities(routing_domain, CONNECTIVITY_CAPABILITIES) {
            self.connectivity_capabilities.add_entry(e);
        }
        if e.has_all_capabilities(routing_domain, DISTANCE_METRIC_CAPABILITIES) {
            self.distance_metric_capabilities.add_entry(e);
        }
    }
}

impl fmt::Display for EntrySummaryDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "any_capabilities: {}\nconnectivity_capabilities: {}\ndistance_metric_capabilities: {}",
            self.any_capabilities,
            self.connectivity_capabilities,
            self.distance_metric_capabilities,
        )
    }
}

/// Keeping track of how many entries we have of each type we care about in a specific routing domain
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct EntrySummary {
    /// A count of the entries in the routing domain per crypto kind
    pub per_crypto_kind: BTreeMap<CryptoKind, EntrySummaryDetail>,
    /// A count of the entries in the routing domain with any crypto kind
    pub all: EntrySummaryDetail,
}

impl EntrySummary {
    pub(in crate::routing_table) fn new() -> Self {
        Self::default()
    }

    pub(in crate::routing_table) fn add_entry(
        &mut self,
        routing_domain: RoutingDomain,
        e: &BucketEntrySnapshot,
    ) {
        for crypto_kind in e.crypto_kinds() {
            let detail = self.per_crypto_kind.entry(crypto_kind).or_default();

            detail.add_entry(routing_domain, e);
        }
    }
}

impl fmt::Display for EntrySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (ck, detail) in self.per_crypto_kind.iter() {
            write!(f, "{:?}:\n{}\n", ck, indent_all_string(detail))?;
        }
        write!(f, "all:\n{}\n", indent_all_string(&self.all))
    }
}
