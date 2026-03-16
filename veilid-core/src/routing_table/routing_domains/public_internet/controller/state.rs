use super::*;

impl_veilid_log_facility!("rtab");

/// Minimum number of nodes we need, per crypto kind or we trigger a bootstrap
const MIN_BOOTSTRAP_CONNECTIVITY_PEERS: usize = 4;
/// Fraction of the total nodes we need to have tested to allocate routes
const ALLOCATION_TOTAL_NODES_TESTED_FACTOR: f32 = 0.5;
/// Fraction of the low water mark nodes we need to have tested to allocate routes
const ALLOCATION_LOW_WATER_MARK_NODES_TESTED_FACTOR: f32 = 0.8;

/// Description of which nodes this routing domain needs per crypto kind to operate properly
pub struct NodesNeeded {
    pub needs_bootstrap: Vec<CryptoKind>,
    pub needs_peer_minimum_refresh: Vec<CryptoKind>,
    pub needs_more_tested_nodes: Vec<CryptoKind>,
}

impl PublicInternetRoutingDomainController {
    pub fn state(&self) -> RoutingDomainState {
        let (
            relay_status,
            current_peer_info,
            confirmed,
            address_types,
            outbound_protocols,
            entry_summary,
            relays,
        ) = {
            let detail = self.read();
            let relay_status = detail.relay_status();
            let current_peer_info = detail.get_peer_info();
            let confirmed = detail.confirmed();
            let address_types = detail.address_types();
            let outbound_protocols = detail.outbound_protocols();
            let entry_summary = detail.get_entry_summary();
            let relays = detail.relays();

            (
                relay_status,
                current_peer_info,
                confirmed,
                address_types,
                outbound_protocols,
                entry_summary,
                relays,
            )
        };

        // Determine inbound stage
        let inbound_stage = {
            if !confirmed {
                if address_types.is_empty() || outbound_protocols.is_empty() {
                    RoutingDomainInboundStage::Invalid
                } else {
                    RoutingDomainInboundStage::NeedsDialInfoConfirmation
                }
            } else if address_types.is_empty() || outbound_protocols.is_empty() {
                RoutingDomainInboundStage::Unusable
            } else if relay_status.needs_more_relays() && relays.is_empty() {
                // If relays are wanted, they are all allocated at the same time, so we either have all the relays
                // we need, or we don't have any at all
                RoutingDomainInboundStage::NeedsRelays
            } else {
                RoutingDomainInboundStage::ReadyToPublish
            }
        };

        // Determine outbound stage
        let outbound_stage = {
            if address_types.is_empty()
                || outbound_protocols.is_empty()
                || !self.network_manager().network_is_started()
            {
                RoutingDomainOutboundStage::Invalid
            } else {
                // Figure out if we need more nodes
                let nodes_needed = self.nodes_needed();
                if !nodes_needed.needs_bootstrap.is_empty() {
                    RoutingDomainOutboundStage::NeedsBootstrap
                } else if self.get_published_peer_info().is_none() {
                    RoutingDomainOutboundStage::NeedsPublishedPeerInfo
                } else if !nodes_needed.needs_more_tested_nodes.is_empty() {
                    RoutingDomainOutboundStage::NeedsMoreTestedNodes
                } else if !self.safety_routes_ready() {
                    RoutingDomainOutboundStage::NeedsSafetyRoutes
                } else {
                    RoutingDomainOutboundStage::ReadyToOperate
                }
            }
        };

        let is_ready_inbound = matches!(inbound_stage, RoutingDomainInboundStage::ReadyToPublish);
        let is_ready_outbound =
            matches!(outbound_stage, RoutingDomainOutboundStage::ReadyToOperate);

        RoutingDomainState {
            inbound_stage,
            outbound_stage,
            relay_status,
            current_peer_info,
            entry_summary,
            is_ready_inbound,
            is_ready_outbound,
        }
    }

    /// Figure out if we need more nodes for this routing domain
    pub(in crate::routing_table) fn nodes_needed(&self) -> NodesNeeded {
        // Nodes needed summary is based off the entry summary and the low water mark
        let (entry_summary, low_water_mark) = {
            let rdd = self.read();
            (rdd.get_entry_summary(), rdd.get_low_water_mark())
        };

        // Calculate which crypto kinds we need more nodes for
        let mut needs_bootstrap = Vec::new();
        let mut needs_peer_minimum_refresh = Vec::new();
        let mut needs_more_tested_nodes = Vec::new();

        let min_peer_count = self.config().network.dht.min_peer_count as usize;
        for ck in VALID_CRYPTO_KINDS {
            // See if we need bootstrap or peer minimum refresh
            let cnt = entry_summary
                .per_crypto_kind
                .get(&ck)
                .map(|x| x.connectivity_capabilities.live)
                .unwrap_or_default();
            if cnt < MIN_BOOTSTRAP_CONNECTIVITY_PEERS {
                needs_bootstrap.push(ck);
            } else if cnt < min_peer_count {
                needs_peer_minimum_refresh.push(ck);
            }

            // See if we need more tested nodes
            let any_capabilities_nodes = entry_summary
                .per_crypto_kind
                .get(&ck)
                .map(|x| x.any_capabilities)
                .unwrap_or_default();
            let low_water_mark_count = low_water_mark.get(ck).unwrap_or_default();
            let required_tested_total_nodes = (any_capabilities_nodes.live as f32
                * ALLOCATION_TOTAL_NODES_TESTED_FACTOR)
                as usize;
            let required_tested_low_water_mark_nodes = (low_water_mark_count as f32
                * ALLOCATION_LOW_WATER_MARK_NODES_TESTED_FACTOR)
                as usize;
            let required_tested_nodes = usize::max(
                required_tested_total_nodes,
                required_tested_low_water_mark_nodes,
            );
            if any_capabilities_nodes.tested < required_tested_nodes {
                needs_more_tested_nodes.push(ck);
            }
        }

        NodesNeeded {
            needs_bootstrap,
            needs_peer_minimum_refresh,
            needs_more_tested_nodes,
        }
    }
}
