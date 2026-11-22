//! Browser (wasm) WebTransport client, outbound only.
//!
//! A browser node connects out to a directly reachable peer's WebTransport endpoint by IP and
//! pins the peer's self-signed certificate by SHA-256 hash through `serverCertificateHashes`.
//! The hashes come from the peer's dial info. The framing matches the native handler so the
//! two interoperate:
//! - `WTS` (stream): one bidirectional stream carries a 4-byte big-endian length prefix
//!   followed by the message bytes.
//! - `WTD` (datagram): messages are framed with the shared [`AssemblyBuffer`], the same
//!   reassembly layer raw UDP uses. Each 8-byte frame header self-describes
//!   sequence/offset/total-length, so a message that fits one datagram costs only that
//!   header, while a larger message (up to `MAX_MESSAGE_SIZE`) is split into fragments
//!   sized from the session's live `max_datagram_size()`. That budget is read fresh on
//!   every send, since a browser silently discards a datagram write that exceeds the current
//!   budget instead of erroring, so the fragment size cannot be a constant.
//!
//! Browsers cannot listen, so there is no accept path here; inbound to a browser node
//! still goes through a relay. The web-sys WebTransport API is unstable, so this is
//! built with `--cfg=web_sys_unstable_apis`.

use super::*;
use futures_util::future::{select, Either};
use send_wrapper::SendWrapper;
use std::io;
use wasm_bindgen::prelude::*;
use web_transport_wasm::{RecvStream, SendStream, Session};

impl_veilid_log_facility!("net");

/// Bytes of big-endian length that precede a message on a WTS stream, which the reader takes
/// first to learn how much body to collect.
const STREAM_LEN_PREFIX: usize = size_of::<u32>();

/// How long a single write may stay pending before the session is treated as gone, since a
/// browser can leave a write promise unresolved instead of rejecting it.
const WT_SEND_TIMEOUT_MS: u32 = 5_000;

/// How much of a stream write is handed to the browser at a time, so each piece gets its own
/// [`WT_SEND_TIMEOUT_MS`] deadline instead of a whole large message sharing one.
const WT_STREAM_CHUNK_SIZE: usize = 16 * 1024;

/// The smallest datagram budget the WTD path will send on, below which the room left after the
/// fragment header is too small to carry a message in a workable number of fragments.
const MIN_WTD_DATAGRAM_SIZE: usize = 256;

fn js_io_error(e: JsValue) -> io::Error {
    io::Error::other(format!("{:?}", e))
}

enum WebTransportChannel {
    Stream {
        send: AsyncMutex<SendStream>,
        recv: AsyncMutex<RecvStream>,
    },
    Datagram {
        assembly: AssemblyBuffer,
    },
}

struct WebTransportNetworkConnectionInner {
    session: Session,
    channel: WebTransportChannel,
}

/// web-transport-wasm's `Session` leaves the browser transport open on drop, and an unclosed
/// session holds a WebTransport slot until the browser times it out; enough of them jam every
/// later WebTransport dial on the page
impl Drop for WebTransportNetworkConnectionInner {
    fn drop(&mut self) {
        self.session.close(0, "close");
    }
}

#[derive(Clone)]
pub struct WebTransportNetworkConnection {
    registry: VeilidComponentRegistry,
    flow: Flow,
    /// The session and its streams hold `Rc` state that the browser thread owns, so the
    /// connection carries them the same way its futures travel.
    inner: Arc<SendWrapper<WebTransportNetworkConnectionInner>>,
}

impl fmt::Debug for WebTransportNetworkConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportNetworkConnection")
            .field("flow", &self.flow)
            .finish()
    }
}

impl_veilid_component_accessors!(WebTransportNetworkConnection);

impl WebTransportNetworkConnection {
    pub fn flow(&self) -> Flow {
        self.flow
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "protocol", err, skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn close(&self) -> io::Result<NetworkResult<()>> {
        veilid_log!(self trace "WebTransport(wasm): close {:?}", self.flow);
        let inner = self.inner.clone();
        SendWrapper::new(async move {
            inner.session.close(0, "close");
            Ok(NetworkResult::value(()))
        })
        .await
    }

    /// Finishes the stream and waits for the peer to acknowledge it, bounded by
    /// `connection_initial_timeout_ms`, then closes; a browser reports nothing when a datagram
    /// leaves, so a datagram session closes at once
    pub fn flush_and_close(&self) -> impl Future<Output = ()> + Send + 'static {
        let timeout_ms = self
            .config()
            .internal()
            .network
            .connection_initial_timeout_ms;
        let inner = self.inner.clone();
        SendWrapper::new(async move {
            if let WebTransportChannel::Stream { send, .. } = &inner.channel {
                let mut send = send.lock().await;
                let _ = send.finish();
                // The writer's closed promise settles once the peer acknowledges the FIN
                let _ = timeout(timeout_ms, send.closed()).await;
            }
            inner.session.close(0, "close");
        })
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "protocol", err, skip(self, message), fields(__VEILID_LOG_KEY = self.log_key(), message.len = message.len()))
    )]
    pub async fn send(&self, message: Bytes) -> io::Result<NetworkResult<()>> {
        if message.len() > MAX_MESSAGE_SIZE {
            veilid_log!(self debug
                "WebTransport(wasm): refusing to send too large message ({} bytes) {:?}",
                message.len(), self.flow);
            bail_io_error_other!("sending too large WebTransport message");
        }
        let inner = self.inner.clone();
        let registry = self.registry();
        let flow = self.flow;
        // Every WebTransport await holds a `JsFuture`, which holds an `Rc`, so this future is
        // `!Send` and only a `SendWrapper` satisfies the `PinBoxFuture` the trait returns.
        SendWrapper::new(async move {
            match &inner.channel {
                WebTransportChannel::Stream { send, .. } => {
                    let mut stream = send.lock().await;
                    let len = (message.len() as u32).to_be_bytes();
                    if let Err(err) = chunked_write(&inner.session, &mut stream, &len).await {
                        veilid_log!(registry debug
                            "WebTransport(wasm): stream length write failed {:?}: {}", flow, err);
                        return Ok(NetworkResult::no_connection(err));
                    }
                    if let Err(err) = chunked_write(&inner.session, &mut stream, &message).await {
                        veilid_log!(registry debug
                            "WebTransport(wasm): stream body write failed {:?}: {}", flow, err);
                        return Ok(NetworkResult::no_connection(err));
                    }
                    Ok(NetworkResult::value(()))
                }
                WebTransportChannel::Datagram { assembly } => {
                    let max = inner.session.max_datagram_size();
                    if max < MIN_WTD_DATAGRAM_SIZE {
                        veilid_log!(registry debug
                            "WebTransport(wasm): datagram budget collapsed ({} < {}) {:?}",
                            max, MIN_WTD_DATAGRAM_SIZE, flow);
                        return Ok(NetworkResult::no_connection_other(
                            "WebTransport datagram budget too small",
                        ));
                    }
                    let remote_addr = flow.remote_address().socket_addr();
                    let session = inner.session.clone();
                    let sender = move |framed_chunk: Bytes, _remote_addr: SocketAddr| {
                        let session = session.clone();
                        let registry = registry.clone();
                        async move {
                            let sent = bounded_write(
                                &session,
                                "datagram send",
                                session.send_datagram(framed_chunk),
                            )
                            .await;
                            match sent {
                                Ok(()) => Ok(NetworkResult::value(())),
                                Err(err) => {
                                    veilid_log!(registry debug
                                        "WebTransport(wasm): datagram send failed {:?}: {}", flow, err);
                                    Ok(NetworkResult::no_connection(err))
                                }
                            }
                        }
                    };
                    assembly
                        .split_message(message, remote_addr, max, sender)
                        .await
                }
            }
        })
        .await
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "protocol", err, skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn recv(&self) -> io::Result<NetworkResult<Bytes>> {
        let inner = self.inner.clone();
        let registry = self.registry();
        let flow = self.flow;
        SendWrapper::new(async move {
            match &inner.channel {
                WebTransportChannel::Stream { recv, .. } => {
                    let mut stream = recv.lock().await;
                    let len_buf = match read_exact(&mut stream, STREAM_LEN_PREFIX).await? {
                        Some(b) => b,
                        None => {
                            veilid_log!(registry debug
                                "WebTransport(wasm): stream closed reading length {:?}", flow);
                            return Ok(NetworkResult::no_connection(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "WebTransport stream closed",
                            )))
                        }
                    };
                    let len = u32::from_be_bytes(len_buf[..].try_into().unwrap()) as usize;
                    if len > MAX_MESSAGE_SIZE {
                        veilid_log!(registry debug
                            "WebTransport(wasm): received too large stream message ({} bytes) {:?}",
                            len, flow);
                        return Ok(NetworkResult::invalid_message(
                            "too large WebTransport stream message",
                        ));
                    }
                    match read_exact(&mut stream, len).await? {
                        Some(payload) => Ok(NetworkResult::Value(Bytes::from(payload))),
                        None => {
                            veilid_log!(registry debug
                                "WebTransport(wasm): stream closed mid-message {:?}", flow);
                            Ok(NetworkResult::no_connection(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "WebTransport stream closed mid-message",
                            )))
                        }
                    }
                }
                WebTransportChannel::Datagram { assembly } => {
                    let remote_addr = flow.remote_address().socket_addr();
                    loop {
                        let data = match inner.session.recv_datagram().await {
                            Ok(data) => data,
                            Err(e) => {
                                let err = to_io_error_other(e);
                                veilid_log!(registry debug
                                    "WebTransport(wasm): datagram read failed {:?}: {}", flow, err);
                                return Ok(NetworkResult::no_connection(err));
                            }
                        };
                        // A raw datagram cannot exceed the transport MTU, so only the
                        // reassembled message needs a size bound.
                        match assembly.insert_frame(&data, remote_addr) {
                            NetworkResult::Value(Some(msg)) => {
                                if msg.len() > MAX_MESSAGE_SIZE {
                                    veilid_log!(registry debug
                                        "WebTransport(wasm): received too large datagram message ({} bytes) {:?}",
                                        msg.len(), flow);
                                    return Ok(NetworkResult::invalid_message(
                                        "too large WebTransport datagram message",
                                    ));
                                }
                                return Ok(NetworkResult::Value(msg));
                            }
                            NetworkResult::Value(None) => continue,
                            NetworkResult::InvalidMessage(s) => {
                                veilid_log!(registry debug
                                    "WebTransport(wasm): dropping invalid WTD frame {:?}: {}", flow, s);
                                continue;
                            }
                            NetworkResult::Timeout => return Ok(NetworkResult::Timeout),
                            NetworkResult::ServiceUnavailable(s) => {
                                return Ok(NetworkResult::ServiceUnavailable(s))
                            }
                            NetworkResult::NoConnection(e) => {
                                return Ok(NetworkResult::NoConnection(e))
                            }
                            NetworkResult::AlreadyExists(e) => {
                                return Ok(NetworkResult::AlreadyExists(e))
                            }
                        }
                    }
                }
            }
        })
        .await
    }
}

/// A browser can leave a WebTransport write promise pending forever instead of rejecting it:
/// Firefox does this for a write blocked on stream flow control when the session closes
/// underneath it, and a caller awaiting the promise alone waits forever. `write` is the write
/// future, a [`SendStream::write`] or a [`Session::send_datagram`], and `what` names it in the
/// error text.
///
/// Losing the race drops the wasm-side future, not the browser's write, so the chunk may still
/// reach the wire and the framing state afterwards is indeterminate.
async fn bounded_write<F>(session: &Session, what: &str, write: F) -> io::Result<()>
where
    F: Future<Output = Result<(), web_transport_wasm::Error>>,
{
    match timeout(
        WT_SEND_TIMEOUT_MS,
        select(Box::pin(write), Box::pin(session.closed())),
    )
    .await
    {
        Ok(Either::Left((Ok(()), _))) => Ok(()),
        Ok(Either::Left((Err(e), _))) => Err(to_io_error_other(e)),
        Ok(Either::Right((e, _))) => Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("WebTransport session closed during {}: {}", what, e),
        )),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "WebTransport {} timed out after {}ms",
                what, WT_SEND_TIMEOUT_MS
            ),
        )),
    }
}

/// Each chunk carries its own [`WT_SEND_TIMEOUT_MS`] deadline, so a large write that keeps making
/// progress is never cut off while a genuinely stalled one still fails within one window.
async fn chunked_write(session: &Session, stream: &mut SendStream, data: &[u8]) -> io::Result<()> {
    for chunk in data.chunks(WT_STREAM_CHUNK_SIZE) {
        bounded_write(session, "stream write", stream.write(chunk)).await?;
    }
    Ok(())
}

async fn read_exact(stream: &mut RecvStream, n: usize) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(n);
    while buf.len() < n {
        match stream
            .read(n - buf.len())
            .await
            .map_err(to_io_error_other)?
        {
            Some(chunk) if !chunk.is_empty() => buf.extend_from_slice(&chunk),
            _ => return Ok(None),
        }
    }
    Ok(Some(buf))
}

pub(in crate::network_manager) struct WebTransportProtocolHandler {}

impl WebTransportProtocolHandler {
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "protocol", skip(registry), ret, err, fields(__VEILID_LOG_KEY = registry.log_key()))
    )]
    pub async fn connect(
        registry: VeilidComponentRegistry,
        dial_info: DialInfo,
        timeout_ms: u32,
    ) -> io::Result<NetworkResult<ProtocolNetworkConnection>> {
        let conn = network_result_try!(Self::dial(registry.clone(), dial_info, timeout_ms).await?);
        Ok(NetworkResult::Value(
            registry
                .network_manager()
                .chaos()
                // A browser exposes no segment size
                .wrap_connection(
                    Box::new(WasmProtocolNetworkConnection::WebTransport(conn)),
                    None,
                ),
        ))
    }

    pub(in crate::network_manager) async fn dial(
        registry: VeilidComponentRegistry,
        dial_info: DialInfo,
        timeout_ms: u32,
    ) -> io::Result<NetworkResult<WebTransportNetworkConnection>> {
        let (is_stream, cert_hashes) = match &dial_info {
            DialInfo::WebTransportStream(di) => (true, di.cert_hashes.clone()),
            DialInfo::WebTransportDatagram(di) => (false, di.cert_hashes.clone()),
            _ => bail_io_error_other!("invalid dialinfo for webtransport protocol"),
        };
        let request = dial_info.request().unwrap_or_log();
        let url = url::Url::parse(&request).map_err(to_io_error_other)?;
        let hashes: Vec<Vec<u8>> = cert_hashes.iter().map(|h| h.to_vec()).collect();
        let peer_address = dial_info.peer_address();

        // An empty hash list means the peer is CA-signed and validated against the browser's
        // system roots.
        let handle = {
            let options = web_sys::WebTransportOptions::new();
            if !hashes.is_empty() {
                let hash_objs: Vec<web_sys::WebTransportHash> = hashes
                    .into_iter()
                    .map(|hash| {
                        let entry = web_sys::WebTransportHash::new();
                        entry.set_algorithm("sha-256");
                        entry.set_value_u8_array(&js_sys::Uint8Array::new_from_slice(
                            hash.as_slice(),
                        ));
                        entry
                    })
                    .collect();
                options.set_server_certificate_hashes(hash_objs.as_slice());
            }
            match web_sys::WebTransport::new_with_options(url.as_str(), &options) {
                Ok(wt) => wt,
                Err(e) => {
                    let err = js_io_error(e);
                    veilid_log!(registry debug
                        "WebTransport(wasm): connect to {} failed: {}", peer_address, err);
                    return Ok(NetworkResult::no_connection(err));
                }
            }
        };
        let mut close_guard = CloseHandleOnDrop(Some(handle.clone()));

        // `ClientBuilder`/`Client::connect` are not used because they build the handle
        // internally and await `ready()` on it, leaving nothing to close when the dial is
        // abandoned; `CloseHandleOnDrop` needs the handle from the moment it exists.
        let built = SendWrapper::new(timeout(timeout_ms, async move {
            wasm_bindgen_futures::JsFuture::from(handle.ready())
                .await
                .map_err(js_io_error)?;
            let session = web_transport_wasm::Session::new(handle, url);
            let channel = if is_stream {
                let (send, recv) = session.open_bi().await.map_err(to_io_error_other)?;
                WebTransportChannel::Stream {
                    send: AsyncMutex::new(send),
                    recv: AsyncMutex::new(recv),
                }
            } else {
                WebTransportChannel::Datagram {
                    assembly: AssemblyBuffer::new(),
                }
            };
            io::Result::Ok(WebTransportNetworkConnectionInner { session, channel })
        }))
        .await;

        let inner = match built {
            Ok(Ok(inner)) => inner,
            Ok(Err(e)) => {
                veilid_log!(registry debug
                    "WebTransport(wasm): connect to {} failed: {}", peer_address, e);
                return Ok(NetworkResult::no_connection(e));
            }
            Err(_) => {
                veilid_log!(registry debug
                    "WebTransport(wasm): connect to {} timed out after {}ms",
                    peer_address, timeout_ms);
                return Ok(NetworkResult::timeout());
            }
        };
        close_guard.defuse();

        Ok(NetworkResult::Value(WebTransportNetworkConnection {
            registry,
            flow: Flow::new_no_local(peer_address),
            inner: Arc::new(SendWrapper::new(inner)),
        }))
    }

    pub async fn send_recv(
        registry: VeilidComponentRegistry,
        dial_info: DialInfo,
        data: Bytes,
        mtu: u16,
        timeout_ms: u32,
    ) -> io::Result<NetworkResult<Bytes>> {
        match &dial_info {
            DialInfo::WebTransportStream(_) => {}
            DialInfo::WebTransportDatagram(_) => {
                return Ok(NetworkResult::no_connection_other(
                    "WebTransport datagram request/response is not supported",
                ));
            }
            _ => bail_io_error_other!("invalid dialinfo for webtransport protocol"),
        }
        if data.len() > MAX_MESSAGE_SIZE {
            bail_io_error_other!("sending too large WebTransport message");
        }
        let peer_address = dial_info.peer_address();

        let started = Timestamp::now();
        let conn = network_result_try!(Self::dial(registry.clone(), dial_info, timeout_ms).await?);

        let elapsed_ms =
            u32::try_from(Timestamp::now().as_u64().saturating_sub(started.as_u64()) / 1_000)
                .unwrap_or(u32::MAX);
        // Debug chaos sees the exchange on a clone; dropping the last one closes the session
        let chaos_conn = registry.network_manager().chaos().wrap_connection(
            Box::new(WasmProtocolNetworkConnection::WebTransport(conn.clone())),
            None,
        );
        let exchange = async {
            network_result_try!(chaos_conn.send(data, mtu).await?);
            chaos_conn.recv().await
        };
        match timeout(timeout_ms.saturating_sub(elapsed_ms), exchange).await {
            Ok(result) => result,
            Err(_) => {
                veilid_log!(registry debug
                    "WebTransport(wasm): request/response to {} timed out after {}ms",
                    peer_address, timeout_ms);
                Ok(NetworkResult::timeout())
            }
        }
    }
}

/// Abandoning a dial does not close the browser's handle, and an unclosed handle holds a
/// WebTransport slot until the browser times it out, so every failure arm of the dial closes it
/// through this guard and only success defuses it.
struct CloseHandleOnDrop(Option<web_sys::WebTransport>);

impl CloseHandleOnDrop {
    fn defuse(&mut self) {
        self.0 = None;
    }
}

impl Drop for CloseHandleOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.close();
        }
    }
}
