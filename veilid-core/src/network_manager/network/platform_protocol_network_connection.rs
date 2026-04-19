use super::*;

pub type ProtocolNetworkConnection = Box<dyn PlatformProtocolNetworkConnection>;

pub trait PlatformProtocolNetworkConnection: fmt::Debug + Send + Sync {
    fn flow(&self) -> Flow;
    fn close(&self) -> PinBoxFuture<'_, std::io::Result<NetworkResult<()>>>;
    fn send(&self, message: Bytes) -> PinBoxFuture<'_, std::io::Result<NetworkResult<()>>>;
    fn recv(&self) -> PinBoxFuture<'_, std::io::Result<NetworkResult<Bytes>>>;
}
