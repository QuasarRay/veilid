use super::*;

impl NativeNetwork {
    /// Rebuild the WSS acceptors when a certificate file changes, so a renewal is served
    /// without a restart. Handshakes under way finish on the certificate they began with
    pub(super) async fn tls_cert_task_routine(
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

        let Some(current) = self.inner.lock().tls_acceptors.clone() else {
            return Ok(());
        };
        if !current.is_stale() {
            return Ok(());
        }
        let acceptors = match self.load_tls_acceptors() {
            Ok(v) => v,
            Err(e) => {
                // A renewal replaces the files one at a time, so the next tick retries
                veilid_log!(self debug "deferring WSS certificate reload (rebuild failed, will retry): {}", e);
                return Ok(());
            }
        };
        let listener_states = {
            let mut inner = self.inner.lock();
            inner.tls_acceptors = Some(acceptors.clone());
            inner.listener_states.values().cloned().collect::<Vec<_>>()
        };
        for listener_state in listener_states {
            let mut ls = listener_state.write();
            if ls.tls_acceptor.is_some() {
                ls.tls_acceptor = Some(acceptors.for_addr(&ls.addr));
            }
        }
        veilid_log!(self info "reloaded WSS certificates from updated TLS files");
        Ok(())
    }
}
