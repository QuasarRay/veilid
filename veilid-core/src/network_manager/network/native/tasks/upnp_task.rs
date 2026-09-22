use super::*;

impl_veilid_log_facility!("net");

impl NativeNetwork {
    #[cfg_attr(feature = "instrument", instrument(parent = None, level = "trace", target = "net", skip_all, err, fields(__VEILID_LOG_KEY = self.log_key())))]
    pub(super) async fn upnp_task_routine(
        &self,
        _stop_token: StopToken,
        _l: Timestamp,
        _t: Timestamp,
    ) -> EyreResult<()> {
        // Only present when UPnP is enabled
        let Some(igd_manager) = &self.igd_manager else {
            return Ok(());
        };
        let outcome = igd_manager.tick().await?;
        if outcome.needs_restart {
            veilid_log!(self info "upnp port mapping renew failed, triggering network restart");
            let mut inner = self.inner.lock();
            inner.network_needs_restart = true;
        } else if outcome.remapped
            && self.routing_domain_request_confirm_dial_info(RoutingDomain::PublicInternet)
        {
            veilid_log!(self info "upnp port mapping moved, detecting dial info");
        }

        Ok(())
    }
}
