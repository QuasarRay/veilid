use super::*;

/// Network platform instance handle
pub type Network = Arc<dyn PlatformNetwork>;

/// Create a new network platform instance
pub fn new_platform_network(registry: VeilidComponentRegistry) -> Network {
    cfg_if! {
        if #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))] {
            Arc::new(native::NativeNetwork::new(registry))
        } else if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
            Arc::new(wasm::WasmNetwork::new(registry))
        }
    }
}

/// Result of sending data to an existing flow
pub enum SendDataToExistingFlowResult {
    /// Data was sent successfully, returning the unique flow used to send the data
    Sent(UniqueFlow),
    /// Data was not sent successfully, returning the data that was not sent
    NotSent(Bytes),
}

/// Network base implementation trait
///
/// Defines the minimum set of operations required for the NetworkManager component to operate
/// Defined separately for native and WASM targets to account for platform-specific differences
/// The data passed to and from this trait is NOT ENCRYPTED any further. It must be encrypted by
/// the caller and used with CAUTION.
pub trait PlatformNetwork: VeilidComponentRegistryAccessor + Send + Sync {
    /// Start up the network
    ///
    /// Used when attaching the node the network
    fn startup(&self) -> PinBoxFuture<'_, EyreResult<StartupDisposition>>;

    /// Whether or not the network needs to be restarted
    ///
    /// If an operating system resource changes availability in an unrecoverable way,
    /// such as a listening socket being terminated, or an interface being removed,
    /// the network manager will use this method to determine when to restart it.
    fn needs_restart(&self) -> bool;

    /// Checks if if the network has been started up or not
    fn is_started(&self) -> bool;

    /// Marks the network as needing to be restarted
    fn restart_network(&self);

    /// Shut down the network
    ///
    /// Used when detaching the node from the network
    fn shutdown(&self) -> PinBoxFuture<'_, ()>;

    /// Run the network tick tasks
    ///
    /// Must be called by the network manager once per second to trigger any background tasks that are required
    fn tick(&self) -> PinBoxFuture<'_, EyreResult<()>>;

    /// Stop any running background tasks
    ///
    /// Called while shutting down the network to detach the node
    fn cancel_tasks(&self) -> PinBoxFuture<'_, ()>;

    ///////////////////////////////////////////////////////////////////////////////////////////////

    /// Creates a new platform-specific network connection to a given dial info
    ///
    /// Not appropriate for connectionless/datagram-oriented protocols (such as RawUDP)
    fn connect(
        &self,
        local_address: Option<SocketAddr>,
        dial_info: DialInfo,
        timeout_ms: u32,
    ) -> PinBoxFuture<'_, EyreResult<NetworkResult<ProtocolNetworkConnection>>>;

    /// Send data to a dial info, unbound, using a new connection from a random port
    ///
    /// This creates a short-lived connection in the case of connection-oriented protocols
    /// for the purpose of sending this one message.
    /// This bypasses the connection table as it is not a 'node to node' connection.
    /// The caller is resposible for encrypting data before calling this function. USE WITH CAUTION.
    fn send_data_unbound_to_dial_info(
        &self,
        dial_info: DialInfo,
        data: Bytes,
    ) -> PinBoxFuture<'_, EyreResult<NetworkResult<()>>>;

    /// Send and receive data to/from a dial info, unbound, using a new connection from a random port
    ///
    /// Waits for a specified amount of time to receive a single response
    /// This creates a short-lived connection in the case of connection-oriented protocols
    /// for the purpose of sending this one message.
    /// This bypasses the connection table as it is not a 'node to node' connection.
    /// The caller is resposible for encrypting data before calling this function. USE WITH CAUTION.
    fn send_recv_data_unbound_to_dial_info(
        &self,
        dial_info: DialInfo,
        data: Bytes,
        timeout_ms: u32,
    ) -> PinBoxFuture<'_, EyreResult<NetworkResult<Bytes>>>;

    /// Send data to a flow that already exists
    ///
    /// The caller is resposible for encrypting data before calling this function. USE WITH CAUTION.
    fn send_data_to_existing_flow(
        &self,
        flow: Flow,
        data: Bytes,
    ) -> PinBoxFuture<'_, EyreResult<SendDataToExistingFlowResult>>;

    /// Send data directly to a dial info, possibly without knowing which node it is going to
    ///
    /// Returns a flow for the connection used to send the data
    /// The caller is resposible for encrypting data before calling this function. USE WITH CAUTION.
    fn send_data_to_dial_info(
        &self,
        dial_info: DialInfo,
        data: Bytes,
    ) -> PinBoxFuture<'_, EyreResult<NetworkResult<UniqueFlow>>>;

    /// Send hole punch attempt to a specific dialinfo. May not be appropriate for all protocols.
    /// Returns a flow for the connection used to send the data
    fn send_hole_punch(
        &self,
        dial_info: DialInfo,
    ) -> PinBoxFuture<'_, EyreResult<NetworkResult<UniqueFlow>>>;

    /// Determine which -local- address to use for establishing a flow to a given dialinfo
    ///
    /// Returns None if no preferred local address is available or required by the dialinfo
    /// Because a node typically has only one connection/flow per protocol/address-type combination
    /// to any other node, properly using the local address ensures that things like hole-punches and
    /// established NAT flows are used optimally.
    fn get_preferred_local_address(&self, dial_info: &DialInfo) -> Option<SocketAddr>;

    /// Determine which -local- address to use for establishing a flow using a specific protocol and address type combination
    fn get_preferred_local_address_by_key(
        &self,
        pt: ProtocolType,
        at: AddressType,
    ) -> Option<SocketAddr>;

    /// Returns which routing domains are configured to detect when their bound or public addresses change
    fn routing_domains_detecting_address_changes(&self) -> BTreeSet<RoutingDomain>;

    /// Mark a routing domain as needing to confirm its dial info
    ///
    /// On some platforms/protocols this causes a dial info discovery process to be run to ensure the
    /// dialinfo in use is up to date
    fn routing_domain_request_confirm_dial_info(&self, routing_domain: RoutingDomain);
}
