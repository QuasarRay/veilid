use super::*;

impl_veilid_log_facility!("rtab");

/// NodeRef pinned to a single (RoutingDomain, TransportType) pair.
/// Used wherever an RPC must be sent over exactly one specific transport — most
/// notably per-transport reliability pings. The type guarantees single-transport
/// semantics; widening via `to_filtered()` is the deliberate, lossy boundary.
/// Sequencing is implied by the transport's protocol_type and is not stored.
pub(crate) struct TransportNodeRef {
    registry: VeilidComponentRegistry,
    entry: Arc<BucketEntry>,
    transport: TransportType,
    routing_domain: RoutingDomain,
    #[cfg(feature = "tracking")]
    track_id: usize,
}

impl_veilid_component_accessors!(TransportNodeRef);

impl TransportNodeRef {
    pub(super) fn new(
        registry: VeilidComponentRegistry,
        entry: Arc<BucketEntry>,
        transport: TransportType,
        routing_domain: RoutingDomain,
    ) -> Self {
        entry.ref_count.fetch_add(1u32, Ordering::AcqRel);

        Self {
            registry,
            entry,
            transport,
            routing_domain,
            #[cfg(feature = "tracking")]
            track_id: entry.track(),
        }
    }

    #[expect(dead_code)]
    pub fn transport(&self) -> TransportType {
        self.transport
    }

    #[expect(dead_code)]
    pub fn routing_domain(&self) -> RoutingDomain {
        self.routing_domain
    }

    /// Lossy widening to FilteredNodeRef. Recoverable via
    /// `FilteredNodeRef::try_into_transport()`.
    pub fn into_filtered(self) -> FilteredNodeRef {
        let filter = NodeRefFilter::new()
            .with_routing_domain(self.routing_domain)
            .with_protocol_type(self.transport.protocol_type())
            .with_address_type(self.transport.address_type());
        FilteredNodeRef::new(
            self.registry.clone(),
            self.entry.clone(),
            filter,
            Sequencing::NoPreference,
        )
    }

    #[expect(dead_code)]
    pub fn unfiltered(&self) -> NodeRef {
        NodeRef::new(self.registry.clone(), self.entry.clone())
    }
}

impl NodeRefAccessorsTrait for TransportNodeRef {
    fn entry(&self) -> Arc<BucketEntry> {
        self.entry.clone()
    }

    fn sequencing(&self) -> Sequencing {
        Sequencing::NoPreference
    }

    fn routing_domain_set(&self) -> RoutingDomainSet {
        RoutingDomainSet::from(self.routing_domain)
    }

    fn filter(&self) -> NodeRefFilter {
        NodeRefFilter::new()
            .with_routing_domain(self.routing_domain)
            .with_protocol_type(self.transport.protocol_type())
            .with_address_type(self.transport.address_type())
    }

    fn take_filter(&mut self) -> NodeRefFilter {
        self.filter()
    }

    fn dial_info_filter(&self) -> DialInfoFilter {
        DialInfoFilter::all()
            .with_protocol_type(self.transport.protocol_type())
            .with_address_type(self.transport.address_type())
    }
}

impl NodeRefOperateTrait for TransportNodeRef {
    fn operate<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&BucketEntryInner) -> T,
    {
        self.entry.with(f)
    }

    fn operate_mut<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&mut BucketEntryInner) -> T,
    {
        self.entry.with_mut(f)
    }
}

impl NodeRefCommonTrait for TransportNodeRef {}

impl Clone for TransportNodeRef {
    fn clone(&self) -> Self {
        TransportNodeRef::new(
            self.registry.clone(),
            self.entry.clone(),
            self.transport,
            self.routing_domain,
        )
    }
}

impl fmt::Display for TransportNodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let best_node_id = self.entry.with(|e| e.best_node_id());
        write!(
            f,
            "{}+{}/{}",
            f.to_string(best_node_id),
            self.transport,
            f.to_string(self.routing_domain)
        )
    }
}

impl fmt::Debug for TransportNodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportNodeRef")
            .field("node_ids", &self.entry.with(|e| e.node_ids()))
            .field("transport", &self.transport)
            .field("routing_domain", &self.routing_domain)
            .finish()
    }
}

impl Drop for TransportNodeRef {
    fn drop(&mut self) {
        #[cfg(feature = "tracking")]
        self.entry.write().untrack(self.track_id);

        let new_ref_count = self.entry.ref_count.fetch_sub(1u32, Ordering::AcqRel) - 1;
        if new_ref_count == 0 {
            let node_ids = self.entry.with(|e| e.node_ids());
            self.routing_table().queue_bucket_kicks(node_ids);
        }
    }
}

impl core::hash::Hash for TransportNodeRef {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.entry).hash(state);
        self.transport.hash(state);
        self.routing_domain.hash(state);
    }
}

impl PartialEq for TransportNodeRef {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.entry, &other.entry)
            && self.transport == other.transport
            && self.routing_domain == other.routing_domain
    }
}

impl Eq for TransportNodeRef {}
