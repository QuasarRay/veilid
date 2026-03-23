use super::*;

/// Keeping track of how many entries we have of each capability set we care about
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct CapabilityCounts {
    /// A count of the entries in the routing domain per crypto kind with any capabilities
    pub any_capabilities: usize,
    /// A count of the entries in the routing domain per crypto kind with all CONNECTIVITY_CAPABILITIES
    pub connectivity_capabilities: usize,
    /// A count of the entries in the routing domain per crypto kind with all DISTANCE_METRIC_CAPABILITIES
    pub distance_metric_capabilities: usize,
}

impl CapabilityCounts {
    pub(in crate::routing_table) fn new() -> Self {
        Self {
            any_capabilities: 0,
            connectivity_capabilities: 0,
            distance_metric_capabilities: 0,
        }
    }

    pub(in crate::routing_table) fn add_entry(
        &mut self,
        routing_domain: RoutingDomain,
        e: &BucketEntrySnapshot,
    ) {
        self.any_capabilities += 1;
        if e.has_all_capabilities(routing_domain, CONNECTIVITY_CAPABILITIES) {
            self.connectivity_capabilities += 1;
        }
        if e.has_all_capabilities(routing_domain, DISTANCE_METRIC_CAPABILITIES) {
            self.distance_metric_capabilities += 1;
        }
    }

    pub(in crate::routing_table) fn min_assign(&mut self, other: &CapabilityCounts) {
        self.any_capabilities.min_assign(other.any_capabilities);
        self.connectivity_capabilities
            .min_assign(other.connectivity_capabilities);
        self.distance_metric_capabilities
            .min_assign(other.distance_metric_capabilities);
    }
}

impl fmt::Display for CapabilityCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "any={}\nconnectivity={}\ndistance_metric={}",
                self.any_capabilities,
                self.connectivity_capabilities,
                self.distance_metric_capabilities
            )
        } else {
            write!(
                f,
                "{{any={},conn={},dist={}}}",
                self.any_capabilities,
                self.connectivity_capabilities,
                self.distance_metric_capabilities
            )
        }
    }
}

/// Keeping track of how many entries we have of each type we care about per crypto kind
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct EntrySummaryDetail {
    /// A count of the entries in the routing domain per crypto kind
    pub total: CapabilityCounts,
    /// A count of the entries in the routing domain per crypto kind that are live
    pub live: CapabilityCounts,
    /// A count of the entries in the routing domain per crypto kind that have been tested
    pub tested: CapabilityCounts,
}

impl EntrySummaryDetail {
    pub(in crate::routing_table) fn add_entry(
        &mut self,
        routing_domain: RoutingDomain,
        e: &BucketEntrySnapshot,
    ) {
        self.total.add_entry(routing_domain, e);
        if matches!(
            e.state,
            BucketEntryState::Reliable | BucketEntryState::Unreliable
        ) {
            self.live.add_entry(routing_domain, e);
            if e.is_tested() {
                self.tested.add_entry(routing_domain, e);
            }
        }
    }
}

impl fmt::Display for EntrySummaryDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "total: {}\nlive: {}\ntested: {}",
                self.total, self.live, self.tested
            )
        } else {
            write!(
                f,
                "total:{} / live:{} / tested:{}",
                self.total, self.live, self.tested
            )
        }
    }
}

/// Keeping track of how many entries we have of each type we care about in a specific routing domain
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct EntrySummary {
    /// A count of the entries in the routing domain per crypto kind
    pub per_crypto_kind: BTreeMap<CryptoKind, EntrySummaryDetail>,
    /// A count of the entries in the routing domain with any crypto kind
    pub combined: EntrySummaryDetail,
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
        if f.alternate() {
            write!(f, "combined:\n{:#}\n", indent_all_string(&self.combined))?;
            for (ck, detail) in self.per_crypto_kind.iter() {
                write!(f, "{:#}:\n{:#}\n", ck, indent_all_string(detail))?;
            }
            Ok(())
        } else {
            let mut out = Vec::new();
            for (ck, detail) in self.per_crypto_kind.iter() {
                out.push(format!("{}({})", ck, detail));
            }
            // Don't bother with combined for now, trying to fit the health states on one log line
            // if self.per_crypto_kind.len() > 1 {
            //     // Save space if there's only one crypto kind
            //     out.push(format!("combined({})", indent_all_string(&self.combined)));
            // }
            if out.is_empty() {
                out.push("none".to_string());
            }
            write!(f, "{}", out.join(", "))
        }
    }
}
