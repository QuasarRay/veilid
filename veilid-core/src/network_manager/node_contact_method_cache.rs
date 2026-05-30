use super::*;

pub const NODE_CONTACT_METHOD_CACHE_SIZE: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct NodeContactMethodCacheKey {
    /// The node ids associated with this target
    pub node_ids: NodeIdGroup,
    /// The timestamp of our own -current- peer info
    pub own_node_info_ts: Timestamp,
    /// The timestamp our -published- peer info if it has been published
    pub own_published_node_info_ts: Option<Timestamp>,
    /// The timestamp of the target's published peer info
    pub target_node_info_ts: Timestamp,
    /// The node ref filter used to connect to the target
    pub target_node_ref_filter: NodeRefFilter,
    /// The sequencing requirement for connections to the target
    pub target_node_ref_sequencing: Sequencing,
    /// The ordering of dial info failures from least recent to most recent
    pub dial_info_failures: Vec<DialInfo>,
}

#[derive(Copy, Clone, Default, Debug)]
pub struct HitMissStats {
    pub hit: usize,
    pub miss: usize,
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum ContactMethodKind {
    Unreachable,
    Existing,
    Direct,
    SignalReverse,
    SignalHolePunch,
    InboundRelay,
    OutboundRelay,
}
impl From<&NodeContactMethodResult> for ContactMethodKind {
    fn from(value: &NodeContactMethodResult) -> Self {
        match value {
            NodeContactMethodResult::NoRoutingDomain
            | NodeContactMethodResult::NoPeerInfo
            | NodeContactMethodResult::NoContactMethod
            | NodeContactMethodResult::Punished => ContactMethodKind::Unreachable,
            NodeContactMethodResult::Resolved(NodeContactMethod::Existing) => {
                ContactMethodKind::Existing
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::Direct { .. }) => {
                ContactMethodKind::Direct
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::SignalReverse { .. }) => {
                ContactMethodKind::SignalReverse
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::SignalHolePunch { .. }) => {
                ContactMethodKind::SignalHolePunch
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::InboundRelay { .. }) => {
                ContactMethodKind::InboundRelay
            }
            NodeContactMethodResult::Resolved(NodeContactMethod::OutboundRelay { .. }) => {
                ContactMethodKind::OutboundRelay
            }
        }
    }
}

impl HitMissStats {
    pub fn percentage(&self) -> f32 {
        (self.hit as f32 * 100.0f32) / ((self.hit + self.miss) as f32)
    }
}

impl fmt::Display for HitMissStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} {:.2}%",
            self.hit,
            self.hit + self.miss,
            self.percentage()
        )
    }
}

pub struct NodeContactMethodCache {
    cache: hashlink::LruCache<NodeContactMethodCacheKey, NodeContactMethodResult>,

    // Statistics for cache hits/misses
    cache_stats: HitMissStats,

    // Recorded stats for contact method success
    contact_method_kind_stats: HashMap<ContactMethodKind, HitMissStats>,
}

impl fmt::Debug for NodeContactMethodCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeContactMethodCache")
            //.field("cache", &self.cache)
            .field("cache_stats", &self.cache_stats)
            .field("contact_method_kind_stats", &self.contact_method_kind_stats)
            .finish()
    }
}

impl NodeContactMethodCache {
    pub fn new() -> Self {
        Self {
            cache: hashlink::LruCache::new(NODE_CONTACT_METHOD_CACHE_SIZE),
            cache_stats: HitMissStats::default(),
            contact_method_kind_stats: HashMap::new(),
        }
    }
    pub fn insert(
        &mut self,
        ncm_key: NodeContactMethodCacheKey,
        ncm_result: NodeContactMethodResult,
    ) {
        self.cache.insert(ncm_key, ncm_result);
    }

    pub fn get(&mut self, ncm_key: &NodeContactMethodCacheKey) -> Option<NodeContactMethodResult> {
        if let Some(ncm_result) = self.cache.get(ncm_key) {
            self.cache_stats.hit += 1;
            return Some(ncm_result.clone());
        }
        self.cache_stats.miss += 1;
        None
    }

    pub fn record_contact_method_success(&mut self, ncm_result: &NodeContactMethodResult) {
        let cmk = ContactMethodKind::from(ncm_result);
        self.contact_method_kind_stats.entry(cmk).or_default().hit += 1;
    }
    pub fn record_contact_method_failure(&mut self, ncm_result: &NodeContactMethodResult) {
        let cmk = ContactMethodKind::from(ncm_result);
        self.contact_method_kind_stats.entry(cmk).or_default().miss += 1;
    }

    pub fn debug(&self) -> String {
        let mut out = format!(
            "Cache size: {}\nCache hits: {}\nContact methods:\n",
            self.cache.len(),
            self.cache_stats
        );
        let mut sorted_kinds: Vec<_> = self.contact_method_kind_stats.keys().collect();
        sorted_kinds.sort();
        for kind in sorted_kinds {
            let kindstats = self.contact_method_kind_stats.get(kind).unwrap_or_log();
            out += &format!("  {:?}: {}\n", kind, kindstats);
        }
        out
    }
}
