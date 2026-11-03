use super::*;

impl NativeNetwork {
    pub(super) async fn webtransport_cert_task_routine(
        &self,
        stop_token: StopToken,
        _l: Timestamp,
        _t: Timestamp,
    ) -> EyreResult<()> {
        let _guard = match self
            .network_task_lock
            .write()
            .timeout_at(stop_token.clone())
            .await
        {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        match self.webtransport_cert_mode() {
            WebTransportCertMode::CaSigned(_) => self.maybe_reload_webtransport_ca_certificate(),
            WebTransportCertMode::SelfSigned => {
                self.rotate_self_signed_webtransport_certificate().await
            }
        }
    }

    async fn rotate_self_signed_webtransport_certificate(&self) -> EyreResult<()> {
        let Some(cert_manager) = self.inner.lock().webtransport.certificate_manager.clone() else {
            return Ok(());
        };

        let outcome = cert_manager
            .maintain(Timestamp::now())
            .await
            .map_err(|e| eyre!("webtransport certificate maintenance failed: {}", e))?;

        let (swap_pending, renewal_pending) = {
            let mut inner = self.inner.lock();
            let retries = &mut inner.webtransport.cert_retries;
            retries.latch(&outcome);
            (retries.swap_pending(), retries.renewal_pending())
        };

        if swap_pending {
            if let Some(server_configs) = self.webtransport_server_configs()? {
                self.swap_webtransport_server_configs(server_configs);
                veilid_log!(self info "rotated live WebTransport server certificate");
            }
            self.inner.lock().webtransport.cert_retries.clear_swap();
        }

        if renewal_pending {
            self.renew_webtransport_dial_info(cert_manager.current_advertisement())?;
            self.inner.lock().webtransport.cert_retries.clear_renewal();
            veilid_log!(self debug "renewed WebTransport dial info after certificate rotation");
        }

        Ok(())
    }
}
