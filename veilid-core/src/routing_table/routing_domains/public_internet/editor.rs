use super::*;

impl_veilid_log_facility!("rtab");

#[derive(Debug)]
enum RoutingDomainChangePublicInternet {
    SetInterfaceAddresses { interface_addresses: Vec<IfAddr> },
    Common(RoutingDomainChange),
}

pub struct RoutingDomainEditorPublicInternet<'a> {
    controller: &'a PublicInternetRoutingDomainController,
    changes: Vec<RoutingDomainChangePublicInternet>,
}

impl<'a> VeilidComponentRegistryAccessor for RoutingDomainEditorPublicInternet<'a> {
    fn registry(&self) -> VeilidComponentRegistry {
        self.controller.registry()
    }
}

impl<'a> RoutingDomainEditorPublicInternet<'a> {
    pub(in crate::routing_table) fn new(
        controller: &'a PublicInternetRoutingDomainController,
    ) -> Self {
        Self {
            controller,
            changes: Vec::new(),
        }
    }

    #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), expect(dead_code))]
    pub fn set_interface_addresses(&mut self, interface_addresses: Vec<IfAddr>) -> &mut Self {
        self.changes
            .push(RoutingDomainChangePublicInternet::SetInterfaceAddresses {
                interface_addresses,
            });
        self
    }
}

impl<'a> RoutingDomainEditor for RoutingDomainEditorPublicInternet<'a> {
    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip(self), fields(__VEILID_LOG_KEY = self.log_key())))]
    fn clear_dial_info_details(
        &mut self,
        address_types: Option<AddressTypeSet>,
        protocol_types: Option<ProtocolTypeSet>,
    ) {
        self.changes.push(RoutingDomainChangePublicInternet::Common(
            RoutingDomainChange::ClearDialInfoDetails {
                address_types,
                protocol_types,
            },
        ));
    }
    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip(self), fields(__VEILID_LOG_KEY = self.log_key())))]
    fn set_relay_compilation(&mut self, relay_compilation: Option<RelayCompilation>) {
        self.changes.push(RoutingDomainChangePublicInternet::Common(
            RoutingDomainChange::SetRelayCompilation { relay_compilation },
        ));
    }
    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip(self), fields(__VEILID_LOG_KEY = self.log_key())))]
    fn set_relay_state(&mut self, relay_id: NodeId, state: RoutingDomainRelayState) {
        self.changes.push(RoutingDomainChangePublicInternet::Common(
            RoutingDomainChange::SetRelayState { relay_id, state },
        ));
    }

    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip(self), fields(__VEILID_LOG_KEY = self.log_key())))]
    fn add_dial_info_detail(&mut self, dial_info_detail: DialInfoDetail) {
        self.changes.push(RoutingDomainChangePublicInternet::Common(
            RoutingDomainChange::AddDialInfoDetail { dial_info_detail },
        ));
    }

    // #[cfg_attr(feature = "instrument", instrument(level = "debug", skip(self), fields(__VEILID_LOG_KEY = self.log_key())))]
    // fn remove_dial_info_detail(&mut self, dial_info_detail: DialInfoDetail) {
    //     self.changes.push(RoutingDomainChangePublicInternet::Common(
    //         RoutingDomainChange::RemoveDialInfoDetail { dial_info_detail },
    //     ));
    // }

    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip(self), fields(__VEILID_LOG_KEY = self.log_key())))]
    fn set_network_config(&mut self, network_config: RoutingDomainNetworkConfig) {
        self.changes.push(RoutingDomainChangePublicInternet::Common(
            RoutingDomainChange::SetNetworkConfig { network_config },
        ));
    }

    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip(self), fields(__VEILID_LOG_KEY = self.log_key())))]
    fn set_confirmed(&mut self, confirmed: bool) {
        self.changes.push(RoutingDomainChangePublicInternet::Common(
            RoutingDomainChange::SetConfirmed { confirmed },
        ));
    }

    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip(self), fields(__VEILID_LOG_KEY = self.log_key())))]
    fn commit(&mut self) {
        // No locking if we have nothing to do
        if self.changes.is_empty() {
            return;
        }
        let routing_table = self.routing_table();

        // Apply changes
        let mut dial_info_changed = false;
        let mut relays_changed = false;
        let mut confirmation_changed = false;
        let mut other_peer_info_changed = false;
        let peer_info_changed: bool;
        {
            let mut rdd = self.controller.write_dyn();
            let Some(detail) = rdd
                .as_any_mut()
                .downcast_mut::<PublicInternetRoutingDomainDetail>()
            else {
                veilid_log!(self error "Failed to downcast routing domain detail to PublicInternetRoutingDomainDetail");
                return;
            };
            {
                let old_dial_info_details = detail.dial_info_details().clone();
                let old_relays = detail.relays();
                let old_outbound_protocols = detail.outbound_protocols();
                let old_inbound_protocols = detail.inbound_protocols();
                let old_address_types = detail.address_types();
                let old_capabilities = detail.capabilities();
                let old_confirmed = detail.confirmed();

                for change in self.changes.drain(..) {
                    match change {
                        RoutingDomainChangePublicInternet::Common(common_change) => {
                            detail.apply_change(common_change);
                        }
                        RoutingDomainChangePublicInternet::SetInterfaceAddresses {
                            interface_addresses,
                        } => {
                            detail.set_interface_addresses(interface_addresses);
                        }
                    }
                }

                let new_dial_info_details = detail.dial_info_details().clone();
                let new_relays = detail.relays();
                let new_outbound_protocols = detail.outbound_protocols();
                let new_inbound_protocols = detail.inbound_protocols();
                let new_address_types = detail.address_types();
                let new_capabilities = detail.capabilities();
                let new_confirmed = detail.confirmed();

                // Compare and see if peerinfo needs republication
                let removed_dial_info = old_dial_info_details
                    .iter()
                    .filter(|di| !new_dial_info_details.contains(di))
                    .collect::<Vec<_>>();
                if !removed_dial_info.is_empty() {
                    veilid_log!(self info
                        "[PublicInternet] removed dial info:\n{}",
                        indent_all_string(removed_dial_info.to_multiline_string())
                            .strip_trailing_newline()
                    );
                    dial_info_changed = true;
                }
                let added_dial_info = new_dial_info_details
                    .iter()
                    .filter(|di| !old_dial_info_details.contains(di))
                    .collect::<Vec<_>>();
                if !added_dial_info.is_empty() {
                    veilid_log!(self info
                        "[PublicInternet] added dial info:\n{}",
                        indent_all_string(added_dial_info.to_multiline_string())
                            .strip_trailing_newline()
                    );
                    dial_info_changed = true;
                }
                if old_relays.len() != new_relays.len()
                    || old_relays
                        .iter()
                        .zip(new_relays.iter())
                        .any(|x| !x.0.relay_node.same_entry(&x.1.relay_node))
                {
                    veilid_log!(self info "[PublicInternet] relays changed: [{}] -> [{}]",
                            old_relays.iter().map(|x| x.relay_node.to_string()).collect::<Vec<_>>().join(","),
                            new_relays.iter().map(|x| x.relay_node.to_string()).collect::<Vec<_>>().join(","));
                    relays_changed = true;
                }
                if old_outbound_protocols != new_outbound_protocols {
                    veilid_log!(self info
                        "[PublicInternet] changed network: outbound {:?}->{:?}",
                        old_outbound_protocols, new_outbound_protocols
                    );
                    other_peer_info_changed = true;
                }
                if old_inbound_protocols != new_inbound_protocols {
                    veilid_log!(self info
                        "[PublicInternet] changed network: inbound {:?}->{:?}",
                        old_inbound_protocols, new_inbound_protocols
                    );
                    other_peer_info_changed = true;
                }
                if old_address_types != new_address_types {
                    veilid_log!(self info
                        "[PublicInternet] changed network: address types {:?}->{:?}",
                        old_address_types, new_address_types
                    );
                    other_peer_info_changed = true;
                }
                if old_capabilities != new_capabilities {
                    veilid_log!(self info
                        "[PublicInternet] changed network: capabilities {:?}->{:?}",
                        old_capabilities, new_capabilities
                    );
                    other_peer_info_changed = true;
                }
                if old_confirmed != new_confirmed {
                    veilid_log!(self info
                        "[PublicInternet] changed confirmation: {:?}->{:?}",
                        old_confirmed, new_confirmed
                    );
                    confirmation_changed = true;
                }
            }

            peer_info_changed = dial_info_changed
                || relays_changed
                || confirmation_changed
                || other_peer_info_changed;

            // Invalidate the caches so we re-generate cached peerinfo and relay status
            if peer_info_changed {
                detail.invalidate();
            }
        }

        if peer_info_changed {
            // Allow signed node info updates at same timestamp for otherwise dead nodes if our network has changed
            routing_table
                .inner
                .write()
                .reset_all_updated_since_last_network_change();

            // Update protections
            self.network_manager()
                .connection_manager()
                .update_protections();

            if let Err(e) = self.event_bus().post(RoutingDomainCommitEvent {
                routing_domain: RoutingDomain::PublicInternet,
                peer_info_changed,
                confirmation_changed,
                dial_info_changed,
                relays_changed,
            }) {
                veilid_log!(self warn "failed to post RoutingDomainCommitEvent: {}", e);
            }
        }
    }

    #[cfg_attr(feature = "instrument", instrument(level = "debug", skip(self), fields(__VEILID_LOG_KEY = self.log_key())))]
    fn reset(&mut self) {
        self.clear_dial_info_details(None, None);
        self.set_relay_compilation(None);
        self.set_confirmed(false);
        self.commit();
    }
}
