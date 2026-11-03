use super::test_bootstrap::register_current_and_expired;
use super::*;
use crate::network_manager::network::native::discovery_context::make_validator_entry_filters;
use crate::tests::*;

pub async fn test_expired_peer_info_is_not_a_dial_info_validator() {
    let registry = mock_registry::init("dial_info_validator_expiration").await;
    {
        let routing_table = registry.routing_table();
        let (current, expired) = register_current_and_expired(&routing_table);

        let filters = VecDeque::from(make_validator_entry_filters(RoutingDomain::PublicInternet));
        let validators = routing_table.find_fast_non_local_nodes_filtered(
            RoutingDomain::PublicInternet,
            2,
            filters,
        );
        let validator_node_ids: Vec<NodeIdGroup> =
            validators.iter().map(|nr| nr.node_ids()).collect();

        assert!(
            validator_node_ids.contains(current.node_ids()),
            "a node whose peer info has not expired must still be usable as a validator: \
             {validator_node_ids:?}"
        );
        assert!(
            !validator_node_ids.contains(expired.node_ids()),
            "a node whose peer info has expired must not be asked to validate dial info: \
             {validator_node_ids:?}"
        );
    }
    mock_registry::terminate(registry).await;
}
