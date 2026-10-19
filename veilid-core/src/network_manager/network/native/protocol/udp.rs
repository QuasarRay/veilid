use super::*;
use stop_token::{StopSource, StopToken};

impl_veilid_log_facility!("net");

/// Consecutive failed receives before this handler gives up and reports an error upward.
///
/// `into_network_result` classifies host-unreachable, not-connected and friends as conditions
/// rather than errors, which is right for one packet and wrong for a socket that returns one
/// every time: an interface torn down under a bound socket leaves `recv_from` failing instantly
/// and permanently. Only an `Err` out of here reaches the listener's own consecutive-error
/// breaker and the network restart behind it.
const UDP_RECV_FAIL_AFTER_CONSECUTIVE_ERRORS: usize = 16;

/// Delay between retries once a receive failure has repeated. Not applied to the first failure:
/// a lone ICMP-driven error is ordinary on a UDP socket and must not add latency to the next
/// packet.
const UDP_RECV_ERROR_BACKOFF_MS: u32 = 100;

#[derive(Clone)]
pub struct RawUdpProtocolHandler {
    /// Component registry for logging and access to other subsystems
    registry: VeilidComponentRegistry,
    /// Low-TTL sends for `socket`, declared before it so its twin closes first
    ttl_sender: Arc<UdpTtlSender>,
    /// Async UDP socket this handler reads from and writes to
    socket: Arc<UdpSocket>,
    /// Reassembly buffer for fragmented UDP messages
    assembly_buffer: AssemblyBuffer,
    /// Drop to signal cancellation; taken out by `stop()`
    stop_source: Arc<Mutex<Option<StopSource>>>,
    /// Cloned by recv-loops that follow this handler's stop
    stop_token: StopToken,
}

impl_veilid_component_accessors!(RawUdpProtocolHandler);

impl RawUdpProtocolHandler {
    pub fn new(registry: VeilidComponentRegistry, socket: Arc<UdpSocket>) -> Self {
        let stop_source = StopSource::new();
        let stop_token = stop_source.token();

        Self {
            registry,
            ttl_sender: Arc::new(UdpTtlSender::new()),
            socket,
            assembly_buffer: AssemblyBuffer::new(),
            stop_source: Arc::new(Mutex::new(Some(stop_source))),
            stop_token,
        }
    }

    /// Stop token for this handler's recv-loop
    pub fn stop_token(&self) -> StopToken {
        self.stop_token.clone()
    }

    /// Signal cancellation for this handler. Idempotent.
    pub fn stop(&self) {
        *self.stop_source.lock() = None;
    }

    /// Debug availability override: a suppressed transport must fail like the network broke it
    fn is_transport_disabled(&self, remote_addr: SocketAddr) -> bool {
        let address_type = if remote_addr.is_ipv6() {
            AddressType::IPV6
        } else {
            AddressType::IPV4
        };
        self.network_manager()
            .transport_stats()
            .is_transport_disabled(LowLevelProtocolType::UDP, address_type)
    }

    #[cfg_attr(feature = "instrument", instrument(level = "trace", target = "protocol", err, skip(self, data), fields(self.socket = ?self.socket, data.len = data.len(), ret.len, ret.flow)))]
    pub async fn recv_message(&self, data: &mut [u8]) -> io::Result<(usize, Flow)> {
        let mut consecutive_errors: usize = 0;
        let (message_len, flow) = loop {
            // Get a packet
            let nres = self.socket.recv_from(data).await.into_network_result()?;
            let failure = (!matches!(nres, NetworkResult::Value(_))).then(|| nres.to_string());
            let (size, remote_addr) = network_result_value_or_log!(self nres => {
                consecutive_errors += 1;
                if consecutive_errors >= UDP_RECV_FAIL_AFTER_CONSECUTIVE_ERRORS {
                    return Err(io::Error::other(format!(
                        "udp recv failed {} times consecutively: {}",
                        consecutive_errors,
                        failure.unwrap_or_default()
                    )));
                }
                // Yield unconditionally: a socket failing instantly would otherwise spin inside a
                // single poll, which pins a core and leaves the stop token unobserved, so the task
                // cannot be cancelled either
                sleep(if consecutive_errors > 1 { UDP_RECV_ERROR_BACKOFF_MS } else { 0 }).await;
                continue;
            });
            consecutive_errors = 0;

            // Check to see if it is punished
            if self
                .network_manager()
                .address_filter()
                .is_ip_addr_punished(remote_addr.ip())
            {
                continue;
            }

            // Insert into assembly buffer
            let message = match self
                .assembly_buffer
                .insert_frame(&data[0..size], remote_addr)
            {
                NetworkResult::Value(Some(v)) => v,
                NetworkResult::Value(None) => {
                    continue;
                }
                nres => {
                    veilid_log!(self debug throttle: PROTOCOL_LOG_THROTTLE_MS, target: "network_result",
                        "UDP::recv_message insert_frame failed: {:?} <= size={} remote_addr={}",
                        nres,
                        size,
                        remote_addr
                    );
                    continue;
                }
            };

            // Check length of reassembled message (same for all protocols)
            if message.len() > MAX_MESSAGE_SIZE {
                veilid_log!(self debug throttle: PROTOCOL_LOG_THROTTLE_MS, "{}({}) at {}@{}:{}", "Invalid message", "received too large UDP message", file!(), line!(), column!());
                continue;
            }

            // Copy assemble message out if we got one
            data[0..message.len()].copy_from_slice(&message);

            // Return a flow and the amount of data in the message
            let peer_addr = PeerAddress::new(
                SocketAddress::from_socket_addr(remote_addr),
                ProtocolType::UDP,
            );
            let local_socket_addr = self.socket.local_addr()?;
            let flow = Flow::new(
                peer_addr,
                SocketAddress::from_socket_addr(local_socket_addr),
            );

            break (message.len(), flow);
        };

        #[cfg(feature = "verbose-tracing")]
        tracing::Span::current().record("ret.len", message_len);
        #[cfg(feature = "verbose-tracing")]
        tracing::Span::current().record("ret.flow", format!("{:?}", flow).as_str());
        Ok((message_len, flow))
    }

    /// Fragment and send a message. `purpose` names the call site in the send-timeout log.
    #[cfg_attr(feature = "instrument", instrument(level = "trace", target = "protocol", err, skip(self, data), fields(self.socket = ?self.socket, data.len = data.len(), ret.flow)))]
    pub async fn send_message(
        &self,
        data: Bytes,
        remote_addr: SocketAddr,
        purpose: &'static str,
    ) -> io::Result<NetworkResult<Flow>> {
        if data.len() > MAX_MESSAGE_SIZE {
            bail_io_error_other!("sending too large UDP message");
        }

        // Check to see if it is punished
        if self
            .network_manager()
            .address_filter()
            .is_ip_addr_punished(remote_addr.ip())
        {
            return Ok(NetworkResult::no_connection_other("punished"));
        }

        if self.is_transport_disabled(remote_addr) {
            return Ok(NetworkResult::no_connection_other("transport disabled"));
        }

        let sender = |framed_chunk: Bytes, remote_addr: SocketAddr| async move {
            let len = network_result_try!(self
                .socket
                .send_to(&framed_chunk, remote_addr)
                .await
                .into_network_result()?);
            if len != framed_chunk.len() {
                bail_io_error_other!("UDP partial send")
            }

            veilid_log!(self trace "udp::send_message:chunk(len={}) {:?}", len, remote_addr);
            Ok(NetworkResult::value(()))
        };

        // A stalled interface parks send_to forever; bound the fragmented send so it fails
        let config = self.registry.config();
        let net_config = &config.internal().network;
        let timeout_ms = net_config
            .rpc
            .timeout_ms
            .min(net_config.single_send_timeout_ms);
        network_result_try!(match timeout(
            timeout_ms,
            self.assembly_buffer
                .split_message(data, remote_addr, sender)
        )
        .await
        {
            Ok(res) => res?,
            Err(_) => {
                veilid_log!(self debug throttle: PROTOCOL_LOG_THROTTLE_MS, "UDP send timed out: purpose={} remote_addr={:?}", purpose, remote_addr);
                return Ok(NetworkResult::timeout());
            }
        });

        // Return a flow for the sent message
        let peer_addr = PeerAddress::new(
            SocketAddress::from_socket_addr(remote_addr),
            ProtocolType::UDP,
        );
        let local_socket_addr = self.socket.local_addr()?;

        let flow = Flow::new(
            peer_addr,
            SocketAddress::from_socket_addr(local_socket_addr),
        );

        veilid_log!(self trace "udp::send_message: {:?}", flow);

        #[cfg(feature = "verbose-tracing")]
        tracing::Span::current().record("ret.flow", format!("{:?}", flow).as_str());
        Ok(NetworkResult::value(flow))
    }

    #[cfg_attr(feature = "instrument", instrument(level = "trace", target = "protocol", err, skip(self), fields(self.socket = ?self.socket, ret.flow)))]
    pub fn send_hole_punch(
        &self,
        remote_addr: SocketAddr,
        ttl: u32,
    ) -> io::Result<NetworkResult<Flow>> {
        // Check to see if it is punished
        if self
            .network_manager()
            .address_filter()
            .is_ip_addr_punished(remote_addr.ip())
        {
            return Ok(NetworkResult::no_connection_other("punished"));
        }

        if self.is_transport_disabled(remote_addr) {
            return Ok(NetworkResult::no_connection_other("transport disabled"));
        }

        // Zero length packet with a best-effort per-packet TTL
        let res = match self
            .ttl_sender
            .send_to(self.socket.as_ref(), &[], remote_addr, ttl)
        {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                veilid_log!(self debug throttle: PROTOCOL_LOG_THROTTLE_MS, "UDP hole punch send would block: remote_addr={:?}", remote_addr);
                return Ok(NetworkResult::timeout());
            }
            res => res,
        };

        // Check for errors
        let len = network_result_try!(res.into_network_result()?);
        if len != 0 {
            bail_io_error_other!("wrong size send");
        }

        // Return a flow for the sent message
        let peer_addr = PeerAddress::new(
            SocketAddress::from_socket_addr(remote_addr),
            ProtocolType::UDP,
        );
        let local_socket_addr = self.socket.local_addr()?;

        let flow = Flow::new(
            peer_addr,
            SocketAddress::from_socket_addr(local_socket_addr),
        );

        veilid_log!(self trace "udp::send_hole_punch: {:?}", flow);

        #[cfg(feature = "verbose-tracing")]
        tracing::Span::current().record("ret.flow", format!("{:?}", flow).as_str());
        Ok(NetworkResult::value(flow))
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "protocol", skip(registry), err, fields(__VEILID_LOG_KEY = registry.log_key()))
    )]
    pub fn try_new_unspecified_bound_handler(
        registry: VeilidComponentRegistry,
        socket_addr: &SocketAddr,
    ) -> io::Result<RawUdpProtocolHandler> {
        // get local wildcard address for bind
        let local_socket_addr = compatible_unspecified_socket_addr(socket_addr);
        let socket = bind_async_udp_socket(local_socket_addr)?
            .ok_or(io::Error::from(io::ErrorKind::AddrInUse))?;
        Ok(RawUdpProtocolHandler::new(registry, Arc::new(socket)))
    }

    /// Bind a UDP socket to a specific local source address
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "protocol", skip(registry), err, fields(__VEILID_LOG_KEY = registry.log_key()))
    )]
    pub fn try_new_specific_bound_handler(
        registry: VeilidComponentRegistry,
        local_socket_addr: SocketAddr,
    ) -> io::Result<RawUdpProtocolHandler> {
        let socket = bind_async_udp_socket(local_socket_addr)?
            .ok_or(io::Error::from(io::ErrorKind::AddrInUse))?;
        Ok(RawUdpProtocolHandler::new(registry, Arc::new(socket)))
    }
}
