use super::*;

impl_veilid_log_facility!("rtab");

pub trait RoutingDomainEditor {
    fn clear_dial_info_details(
        &mut self,
        address_types: Option<AddressTypeSet>,
        protocol_types: Option<ProtocolTypeSet>,
    );
    fn set_relay_compilation(&mut self, relay_compilation: Option<RelayCompilation>);
    fn set_relay_state(&mut self, relay_id: NodeId, state: RoutingDomainRelayState);
    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), expect(dead_code))]
    fn add_dial_info_detail(&mut self, dial_info_detail: DialInfoDetail);
    // #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), expect(dead_code))]
    // fn remove_dial_info_detail(&mut self, dial_info_detail: DialInfoDetail);
    fn set_network_config(&mut self, network_config: RoutingDomainNetworkConfig);
    fn set_confirmed(&mut self, confirmed: bool);
    fn commit(&mut self);
    #[expect(dead_code)]
    fn reset(&mut self);
}

pub(super) trait RoutingDomainDetailApplyChange {
    /// Make a change from the routing domain editor
    fn apply_change(&mut self, change: RoutingDomainChange);
}

impl<T: RoutingDomainDetailAccessors + ?Sized> RoutingDomainDetailApplyChange for T {
    /// Make a change from the routing domain editor
    fn apply_change(&mut self, change: RoutingDomainChange) {
        match change {
            RoutingDomainChange::ClearDialInfoDetails {
                address_types,
                protocol_types,
            } => {
                self.common_mut()
                    .clear_dial_info_details(address_types, protocol_types);
            }

            RoutingDomainChange::SetRelayCompilation { relay_compilation } => {
                self.common_mut().set_relay_compilation(relay_compilation)
            }
            RoutingDomainChange::SetRelayState { relay_id, state } => {
                self.common_mut().set_relay_state(relay_id, state)
            }

            RoutingDomainChange::AddDialInfoDetail { dial_info_detail } => {
                if !self.ensure_dial_info_is_valid(&dial_info_detail.dial_info) {
                    return;
                }

                self.common_mut()
                    .add_dial_info_detail(dial_info_detail.clone());
            }
            // RoutingDomainChange::RemoveDialInfoDetail { dial_info_detail } => {
            //     self.common_mut()
            //         .remove_dial_info_detail(dial_info_detail.clone());
            // }
            RoutingDomainChange::SetNetworkConfig { network_config } => {
                self.common_mut().set_network_config(network_config);
            }
            RoutingDomainChange::SetConfirmed { confirmed } => {
                self.common_mut().set_confirmed(confirmed);
            }
        }
    }
}

#[derive(Debug)]
pub(super) enum RoutingDomainChange {
    ClearDialInfoDetails {
        address_types: Option<AddressTypeSet>,
        protocol_types: Option<ProtocolTypeSet>,
    },
    SetRelayCompilation {
        relay_compilation: Option<RelayCompilation>,
    },
    SetRelayState {
        relay_id: NodeId,
        state: RoutingDomainRelayState,
    },
    AddDialInfoDetail {
        dial_info_detail: DialInfoDetail,
    },
    // #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), expect(dead_code))]
    // RemoveDialInfoDetail {
    //     dial_info_detail: DialInfoDetail,
    // },
    SetNetworkConfig {
        network_config: RoutingDomainNetworkConfig,
    },
    SetConfirmed {
        confirmed: bool,
    },
}
