use super::*;
use crate::network_manager::network::native::low_level_protocol_tcp::ListenerState;
use crate::network_manager::network::native::protocol::tcp::RawTcpProtocolHandler;
use crate::network_manager::network::native::protocol::TcpClose;
use crate::network_manager::network::native::NativeNetwork;
use crate::tests::*;

use futures_util::AsyncReadExt;
use std::io;

const MESSAGE: &[u8] = b"one-shot";

/// `MESSAGE` as a `RawTcp` connection frames it
fn frame() -> Vec<u8> {
    let mut frame = vec![b'V', b'L', MESSAGE.len() as u8, 0];
    frame.extend_from_slice(MESSAGE);
    frame
}

fn loopback_listener() -> (TcpListener, SocketAddr) {
    let any = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let listener = bind_async_tcp_listener(any, None)
        .expect("bind should not error")
        .expect("bind should succeed");
    let addr = listener.local_addr().expect("local addr");
    (listener, addr)
}

fn initial_timeout_ms(registry: &VeilidComponentRegistry) -> u32 {
    registry
        .config()
        .internal()
        .network
        .connection_initial_timeout_ms
}

/// Connects from an unbound port, sends `MESSAGE` and drops the connection, returning the port's
/// address
async fn send_and_drop(
    registry: &VeilidComponentRegistry,
    addr: SocketAddr,
    close: TcpClose,
) -> SocketAddr {
    let connected = RawTcpProtocolHandler::connect(
        registry.clone(),
        None,
        addr,
        initial_timeout_ms(registry),
        close,
    )
    .await
    .expect("connect should not error");
    let NetworkResult::Value(pnc) = connected else {
        panic!("connect should succeed");
    };
    let sent = pnc
        .send(Bytes::from_static(MESSAGE), SAFE_TRANSPORT_MTU)
        .await
        .expect("send should not error");
    assert!(matches!(sent, NetworkResult::Value(())));
    pnc.flow()
        .local()
        .expect("an outbound flow has a local address")
        .socket_addr()
}

/// The receiver of a gracefully closed one-shot send reads the data and then a FIN, not a reset
pub async fn test_graceful_close_ends_with_fin() {
    let registry = mock_registry::init("tcp_one_shot_fin").await;
    let (listener, addr) = loopback_listener();

    send_and_drop(&registry, addr, TcpClose::Graceful).await;

    let (tcp_stream, _) = listener.accept().await.expect("accept");
    let (tcp_stream, _segment_limit) = SegmentLimitedTcpStream::new(tcp_stream);
    let mut stream = AsyncPeekStream::new(tcp_stream);
    let (received, after) = timeout(initial_timeout_ms(&registry), async {
        let mut received = vec![0u8; frame().len()];
        stream.read_exact(&mut received).await.expect("the frame");
        let mut rest = [0u8; 1];
        (received, stream.read(&mut rest).await)
    })
    .await
    .expect("the frame and the close arrive");
    assert_eq!(received, frame());
    assert_eq!(after.expect("a FIN rather than a reset"), 0);

    mock_registry::terminate(registry).await;
}

/// The peer address the acceptor passed a handler and the bytes it left readable
type Accepted = (SocketAddr, Vec<u8>);

/// Takes the frame off an accepted stream and declines the connection
#[derive(Clone)]
struct FrameCapture {
    /// What the acceptor handed over
    captured: Arc<Mutex<Option<Accepted>>>,
}

impl ProtocolAcceptHandler for FrameCapture {
    fn on_accept(
        &self,
        stream: AsyncPeekStream,
        peer_addr: SocketAddr,
        _local_addr: SocketAddr,
    ) -> PinBoxFutureStatic<io::Result<Option<ProtocolNetworkConnection>>> {
        let captured = self.captured.clone();
        Box::pin(async move {
            let mut received = vec![0u8; frame().len()];
            stream.peek_exact(&mut received).await?;
            *captured.lock() = Some((peer_addr, received));
            Ok(None)
        })
    }
}

/// The accept path hands a connection to the protocol handlers with its peer address and data
/// when the peer wrote and reset before the accept
pub async fn test_accept_reads_a_connection_its_peer_reset() {
    let registry = mock_registry::init("tcp_accept_after_reset").await;
    let net = Arc::new(NativeNetwork::new(registry.clone()));
    let (listener, addr) = loopback_listener();

    let client_addr = send_and_drop(&registry, addr, TcpClose::Reset).await;
    // Lets the reset land first; the handlers get the frame either way
    sleep(100).await;
    let accepted = listener.accept().await;

    let captured = Arc::new(Mutex::new(None));
    let mut listener_state = ListenerState::new(addr);
    listener_state
        .protocol_accept_handlers
        .push(Box::new(FrameCapture {
            captured: captured.clone(),
        }));
    NativeNetwork::clone(&net)
        .tcp_acceptor(
            accepted,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(RwLock::new(listener_state)),
            ConnectionManager::new(net),
            initial_timeout_ms(&registry),
            initial_timeout_ms(&registry),
        )
        .await;

    assert_eq!(captured.lock().take(), Some((client_addr, frame())));

    mock_registry::terminate(registry).await;
}

pub async fn test_all() {
    test_graceful_close_ends_with_fin().await;
    test_accept_reads_a_connection_its_peer_reset().await;
}
