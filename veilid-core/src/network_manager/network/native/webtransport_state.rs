use super::webtransport_quinn_runtime::veilid_quinn_client_endpoint;
use super::*;

#[derive(Default)]
pub(super) struct WebTransportState {
    pub(super) certificate_manager: Option<Arc<super::certificate_manager::CertificateManager>>,
    pub(super) cert_retries: WebTransportCertRetries,
    pub(super) endpoints: Vec<web_transport_quinn::quinn::Endpoint>,
    pub(super) client_endpoints: BTreeMap<AddressType, web_transport_quinn::quinn::Endpoint>,
    pub(super) tls_mtimes: Option<Vec<Option<std::time::SystemTime>>>,
    pub(super) shared_bind_mode: bool,
    /// The sockets of dedicated endpoints, keyed by bound address, with the sender their hole
    /// punches leave through
    pub(super) punch_sockets: BTreeMap<SocketAddr, DedicatedPunchSocket>,
}

/// A dedicated WebTransport socket and its hole-punch sender; the sender is declared first so
/// its twins drop before the socket
#[derive(Clone)]
pub(super) struct DedicatedPunchSocket {
    pub(super) ttl_sender: Arc<UdpTtlSender>,
    pub(super) socket: Arc<UdpSocketIo>,
}

/// Follow-up work owed to a certificate rotation, latched until each step is carried out.
#[derive(Default)]
pub(super) struct WebTransportCertRetries {
    swap_server_configs: bool,
    renew_dial_info: bool,
}

impl WebTransportCertRetries {
    pub(super) fn latch(
        &mut self,
        outcome: &super::certificate_manager::CertificateMaintenanceOutcome,
    ) {
        self.swap_server_configs |= outcome.served_certificate_changed;
        self.renew_dial_info |= outcome.current_hashes_changed;
    }

    pub(super) fn swap_pending(&self) -> bool {
        self.swap_server_configs
    }

    pub(super) fn renewal_pending(&self) -> bool {
        self.renew_dial_info
    }

    pub(super) fn clear_swap(&mut self) {
        self.swap_server_configs = false;
    }

    pub(super) fn clear_renewal(&mut self) {
        self.renew_dial_info = false;
    }
}

impl WebTransportState {
    /// Close every WebTransport endpoint, inbound then outbound, and drop the handles.
    ///
    /// Merely dropping the handles leaves quinn's endpoint driver and the shared UDP socket
    /// alive while any connection lingers, because the driver releases the socket only at
    /// `ref_count == 0` with no connections. A restart that rebinds the same port with
    /// `SO_REUSEPORT` could then land inbound flows on the dying socket. `close()` pushes a
    /// Close to every connection so they drain promptly.
    pub(super) fn close_endpoints(&mut self) {
        for endpoint in self.endpoints.drain(..) {
            endpoint.close(0u32.into(), b"network shutdown");
        }
        for (_at, endpoint) in std::mem::take(&mut self.client_endpoints) {
            endpoint.close(0u32.into(), b"network shutdown");
        }
        self.punch_sockets.clear();
    }
}

const CERT_TASK_TICK_PERIOD_SECS: u32 = 60;

pub(super) struct WebTransportTasks {
    pub(super) cert_task: TickTask<EyreReport>,
}

impl WebTransportTasks {
    pub(super) fn new() -> Self {
        Self {
            cert_task: TickTask::new("webtransport_cert_task", CERT_TASK_TICK_PERIOD_SECS),
        }
    }
}

impl NativeNetwork {
    pub(super) async fn startup_webtransport(&self) {
        if let Err(e) = self.startup_certificate_manager().await {
            veilid_log!(self warn
                "WebTransport certificate manager initialization failed; continuing without inbound WebTransport (degraded mode): {}", e);
        }
    }

    pub(super) fn close_webtransport_endpoints(&self, inner: &mut NetworkInner) {
        inner.webtransport.close_endpoints();
    }

    /// The addresses bound for WebTransport, keyed on WTS. Every binding path registers WTS
    /// and WTD at the same address in one call, so either key answers for both.
    pub(in crate::network_manager) fn webtransport_bound_addresses(
        &self,
    ) -> Option<Vec<SocketAddr>> {
        let inner = self.inner.lock();
        let wts = inner.bound_address_per_protocol.get(&ProtocolType::WTS);
        debug_assert_eq!(
            wts,
            inner.bound_address_per_protocol.get(&ProtocolType::WTD),
            "WTS and WTD bound addresses are registered together"
        );
        wts.cloned()
    }

    pub(super) fn opt_webtransport_client_endpoint(
        &self,
        remote: &SocketAddr,
    ) -> Option<web_transport_quinn::quinn::Endpoint> {
        self.webtransport_client_endpoint(remote).ok()
    }

    pub(super) async fn connect_webtransport_unbound(
        &self,
        dial_info: DialInfo,
        connect_timeout_ms: u32,
    ) -> EyreResult<NetworkResult<ProtocolNetworkConnection>> {
        let opt_client_endpoint =
            self.opt_webtransport_client_endpoint(&dial_info.to_socket_addr());
        protocol::webtransport::connect(
            self.registry(),
            None,
            dial_info,
            connect_timeout_ms,
            opt_client_endpoint,
        )
        .await
        .wrap_err("connect failure")
    }

    /// Connect to `dial_info` and send `data` on the new session, without holding on to the
    /// connection.
    ///
    /// WebTransport `send()` only buffers into the quinn driver, so the buffered bytes have to
    /// be flushed before the connection drops or quinn's implicit close abandons them (see
    /// [`spawn_tracked_flush`]).
    pub(super) async fn send_webtransport_unbound(
        &self,
        dial_info: DialInfo,
        data: Bytes,
        mtu: u16,
        connect_timeout_ms: u32,
    ) -> EyreResult<NetworkResult<()>> {
        let opt_client_endpoint =
            self.opt_webtransport_client_endpoint(&dial_info.to_socket_addr());
        let conn = network_result_try!(protocol::webtransport::connect_connection(
            self.registry(),
            None,
            dial_info,
            connect_timeout_ms,
            opt_client_endpoint,
        )
        .await
        .wrap_err("connect failure")?);
        // Debug chaos sees the send on a clone, and the original flushes the shared session
        let chaos_conn = self.network_manager().chaos().wrap_connection(
            Box::new(NativeProtocolNetworkConnection::WebTransport(Box::new(
                conn.clone(),
            ))),
            None,
        );
        network_result_try!(chaos_conn.send(data, mtu).await.wrap_err("send failure")?);
        spawn_tracked_flush(
            &self.startup_lock,
            "WebTransport unbound flush",
            conn.flush_and_close().await,
        );
        Ok(NetworkResult::value(()))
    }

    pub(in crate::network_manager) fn send_quic_hole_punch(
        &self,
        dial_info: &DialInfo,
    ) -> EyreResult<NetworkResult<UniqueFlow>> {
        if !WEBTRANSPORT_PROTOCOL_TYPES.contains(dial_info.protocol_type()) {
            return Ok(NetworkResult::ServiceUnavailable(
                "unimplemented for this protocol".to_owned(),
            ));
        }
        let peer_socket_addr = dial_info.to_socket_addr();
        let Some(local) = self.webtransport_bound_addresses().and_then(|addrs| {
            addrs
                .iter()
                .find(|a| a.is_ipv4() == peer_socket_addr.is_ipv4())
                .copied()
        }) else {
            return Ok(NetworkResult::no_connection_other(
                "no WebTransport-bound UDP socket for the peer's address family",
            ));
        };
        let ttl = hole_punch_ttl(
            &self.config().internal().network,
            &self.interfaces.interface_address_state(),
            dial_info.address_type(),
        );
        // A shared socket punches through its RawUDP handler, a dedicated one through its own sender
        let raw_handler = self.inner.lock().udp_protocol_handlers.get(&local).cloned();
        let flow = match raw_handler {
            Some(ph) => network_result_try!(ph
                .send_hole_punch(peer_socket_addr, ttl)
                .wrap_err("failed to send QUIC hole punch to dial info")?),
            None => network_result_try!(self.send_dedicated_hole_punch(
                local,
                peer_socket_addr,
                dial_info.protocol_type(),
                ttl
            )?),
        };
        Ok(NetworkResult::value(UniqueFlow {
            flow,
            connection_id: None,
            dialed: true,
        }))
    }

    /// The empty TTL-limited datagram a dedicated WebTransport socket punches with
    fn send_dedicated_hole_punch(
        &self,
        local: SocketAddr,
        peer_socket_addr: SocketAddr,
        protocol_type: ProtocolType,
        ttl: u32,
    ) -> EyreResult<NetworkResult<Flow>> {
        let Some(punch_socket) = self
            .inner
            .lock()
            .webtransport
            .punch_sockets
            .get(&local)
            .cloned()
        else {
            return Ok(NetworkResult::no_connection_other(
                "no WebTransport socket bound for QUIC hole punch",
            ));
        };
        if self
            .network_manager()
            .address_filter()
            .is_ip_addr_punished(peer_socket_addr.ip())
        {
            return Ok(NetworkResult::no_connection_other("punished"));
        }
        // Debug chaos can lose the punch, never hold it
        let verdict = self
            .network_manager()
            .chaos()
            .send_verdict(peer_socket_addr.ip(), 0);
        if !matches!(verdict, ChaosVerdict::Drop | ChaosVerdict::Oversize) {
            match punch_socket.ttl_sender.send_to(
                punch_socket.socket.as_ref(),
                &[],
                peer_socket_addr,
                ttl,
            ) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(NetworkResult::timeout());
                }
                Err(e) => return Ok(NetworkResult::no_connection(e)),
            }
        }
        Ok(NetworkResult::value(Flow::new(
            PeerAddress::new(
                SocketAddress::from_socket_addr(peer_socket_addr),
                protocol_type,
            ),
            SocketAddress::from_socket_addr(local),
        )))
    }
}

impl NativeNetwork {
    fn webtransport_client_endpoint(
        &self,
        remote: &SocketAddr,
    ) -> std::io::Result<web_transport_quinn::quinn::Endpoint> {
        let at = if remote.is_ipv4() {
            AddressType::IPV4
        } else {
            AddressType::IPV6
        };
        if let Some(ep) = self.inner.lock().webtransport.client_endpoints.get(&at) {
            return Ok(ep.clone());
        }
        let ep = veilid_quinn_client_endpoint(compatible_unspecified_socket_addr(remote))?;
        let mut inner = self.inner.lock();
        Ok(inner
            .webtransport
            .client_endpoints
            .entry(at)
            .or_insert(ep)
            .clone())
    }

    /// The shared WebTransport quinn endpoint (bound to our shared UDP listen socket)
    /// whose address family matches `peer_socket_addr`, if WebTransport is listening.
    ///
    /// With both a wildcard and a runtime source-bound socket on the same port (via
    /// `SO_REUSEPORT`), the kernel delivers a concrete-addressed QUIC handshake reply to the
    /// source-bound endpoint by longest-prefix match, so `opt_preferred_local` is matched first
    /// and the wildcard endpoint is only a fallback.
    fn webtransport_shared_endpoint(
        &self,
        peer_socket_addr: &SocketAddr,
        opt_preferred_local: Option<SocketAddr>,
    ) -> Option<web_transport_quinn::quinn::Endpoint> {
        let inner = self.inner.lock();
        let family_matches = |ep: &&web_transport_quinn::quinn::Endpoint| {
            ep.local_addr()
                .map(|a| a.is_ipv4() == peer_socket_addr.is_ipv4())
                .unwrap_or(false)
        };
        if let Some(preferred_local) = opt_preferred_local {
            if let Some(ep) = inner.webtransport.endpoints.iter().find(|ep| {
                family_matches(ep)
                    && ep
                        .local_addr()
                        .map(|a| a.ip() == preferred_local.ip())
                        .unwrap_or(false)
            }) {
                return Some(ep.clone());
            }
        }
        inner
            .webtransport
            .endpoints
            .iter()
            .find(family_matches)
            .cloned()
    }

    pub(in crate::network_manager) async fn connect_via_shared_webtransport_endpoint(
        &self,
        dial_info: DialInfo,
        timeout_ms: u32,
    ) -> EyreResult<NetworkResult<ProtocolNetworkConnection>> {
        let _guard = self.startup_lock.enter()?;
        let peer = dial_info.to_socket_addr();
        let opt_preferred_local = self.preferred_outbound_source_addr(&dial_info);
        let Some(endpoint) = self.webtransport_shared_endpoint(&peer, opt_preferred_local) else {
            return Ok(NetworkResult::no_connection_other(
                "no shared WebTransport endpoint for QUIC hole punch",
            ));
        };
        Ok(protocol::webtransport::connect_via_shared_endpoint(
            self.registry(),
            endpoint,
            dial_info,
            timeout_ms,
        )
        .await?)
    }
}

pub(in crate::network_manager) fn spawn_tracked_flush(
    startup_lock: &StartupLock,
    name: &str,
    flush: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let Ok(enter_guard) = startup_lock.enter_arc() else {
        return;
    };
    let stop_token = startup_lock.stop_token();
    spawn_detached(name, async move {
        let _enter_guard = enter_guard;
        match stop_token {
            Some(st) => {
                let _ = flush.timeout_at(st).await;
            }
            None => flush.await,
        }
    });
}
