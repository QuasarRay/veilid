use super::*;

impl_veilid_log_facility!("rtab");

pub trait RoutingDomainController:
    component::VeilidComponentRegistryAccessor + core::any::Any + core::fmt::Debug + Send + Sync
{
    fn as_any(&self) -> &dyn core::any::Any;

    /// The routing domain identifier for this routing domain detail
    fn routing_domain(&self) -> RoutingDomain;

    // Routing Domain Detail Accessors
    ///////////////////////////////////////////////////////////////////////////////////////

    /// Read access to the routing domain detail
    fn read(&self) -> RwLockReadGuard<'_, dyn RoutingDomainDetail>;
    /// Write access to the routing domain detail
    fn write(&self) -> RwLockWriteGuard<'_, dyn RoutingDomainDetail>;

    // Routing Domain Controller Lifecycle
    ///////////////////////////////////////////////////////////////////////////////////////

    /// Start up the routing domain controller
    fn startup(&self) -> PinBoxFuture<'_, EyreResult<()>>;
    /// Shut down the routing domain controller
    fn shutdown(&self) -> PinBoxFuture<'_, ()>;
    /// Run ticker for this domain
    fn tick(&self) -> PinBoxFuture<'_, EyreResult<()>>;
    /// Cancel tasks for this domain
    fn cancel_tasks(&self) -> PinBoxFuture<'_, ()>;

    // Routing Domain Controller Operations
    ///////////////////////////////////////////////////////////////////////////////////////

    /// The state of this routing domain
    fn state(&self) -> RoutingDomainState;
    /// The health status of this domain
    fn get_health(&self) -> RoutingDomainHealth;

    /// Publish current peer info to the world
    fn publish_peer_info(&self) -> bool;
    /// Unpublish peer info from the world
    fn unpublish_peer_info(&self);
    /// Get the published peer info for this routing domain
    fn get_published_peer_info(&self) -> Option<Arc<PeerInfo>>;

    /// Get the contact method required for node A to reach node B in this routing domain
    fn get_contact_method(
        &self,
        peer_a: Arc<PeerInfo>,
        peer_b: Arc<PeerInfo>,
        dial_info_filter: DialInfoFilter,
        sequencing: Sequencing,
        context_sort: Option<&DialInfoDetailSort>,
    ) -> ContactMethod;

    /// Gets the best dial info details, in preference order, to attempt a connection between two nodes
    /// The best available ordering mode is selected from the sequencing constraint,
    /// then the dial info filter is applied, and the available
    /// dial info are then sorted by the context_sort.
    #[cfg_attr(feature = "instrument", instrument(level = "trace", target = "rtab", skip(self, context_sort), fields(__VEILID_LOG_KEY = self.log_key()), ret))]
    fn best_dial_info_details_between_nodes(
        &self,
        from_node: &NodeInfo,
        to_node: &dyn HasDialInfoDetailList,
        dial_info_filter: DialInfoFilter,
        sequencing: Sequencing,
        context_sort: Option<&DialInfoDetailSort>,
    ) -> Vec<DialInfoDetail> {
        // Consider outbound capabilities
        let (ordering, outbound_dial_info_filter) = DialInfoFilter::all()
            .with_address_type_set(from_node.address_types())
            .with_protocol_type_set(from_node.outbound_protocols())
            .apply_sequencing(sequencing);

        // If the filter is dead then we won't be able to connect
        if dial_info_filter.is_dead() {
            return vec![];
        }

        // Get the sort for this ordering mode
        let ordering_sort: Option<Box<DialInfoDetailSort>> =
            DialInfoDetail::get_ordering_sort(ordering);

        // Get all dial info we could possibly connect to for node B with the selected sequencing
        let filter =
            Box::new(|did: &DialInfoDetail| did.matches_filter(&outbound_dial_info_filter));
        let mut all_reachable_dial_info =
            to_node.filtered_dial_info_details(ordering_sort.as_deref(), &filter);

        // Get the best available ordering mode for the reachable dial info
        let Some(best_sequence_ordering) = all_reachable_dial_info
            .iter()
            .map(|x| x.dial_info.protocol_type().sequence_ordering())
            .reduce(|a, b| a.max(b))
        else {
            return vec![];
        };

        // Retain only the dial info with the best sequence ordering and matching the dial info filter
        all_reachable_dial_info.retain(|x| {
            (matches!(sequencing, Sequencing::NoPreference)
                || x.dial_info.protocol_type().sequence_ordering() == best_sequence_ordering)
                && x.matches_filter(&dial_info_filter)
        });

        // Of the remaining candidates, apply the context sort to allow for reordering based on
        // recent dial info failures and any other environmental conditions
        if let Some(context_sort) = context_sort {
            all_reachable_dial_info.sort_by(context_sort);
        }

        // Now return the first dial info detail in the list
        all_reachable_dial_info
    }

    /// Gets the single best dial info detail to attempt a connection between two nodes
    #[cfg_attr(feature = "instrument", instrument(level = "trace", target = "rtab", skip(self, context_sort), fields(__VEILID_LOG_KEY = self.log_key()), ret))]
    fn best_dial_info_detail_between_nodes(
        &self,
        from_node: &NodeInfo,
        to_node: &dyn HasDialInfoDetailList,
        dial_info_filter: DialInfoFilter,
        sequencing: Sequencing,
        context_sort: Option<&DialInfoDetailSort>,
    ) -> Option<DialInfoDetail> {
        let dids = self.best_dial_info_details_between_nodes(
            from_node,
            to_node,
            dial_info_filter,
            sequencing,
            context_sort,
        );
        dids.into_iter().next()
    }
}
