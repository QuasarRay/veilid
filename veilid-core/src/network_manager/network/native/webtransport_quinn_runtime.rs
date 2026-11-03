use super::*;
use std::io::{self, IoSliceMut};
use std::task::{ready, Context, Poll};
use std::time::Instant;
use web_transport_quinn::quinn::{
    self,
    udp::{RecvMeta, Transmit, UdpSocketState},
    AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller,
};

pub(in crate::network_manager) fn veilid_quinn_runtime() -> Arc<dyn Runtime> {
    Arc::new(VeilidQuinnRuntime)
}

pub(in crate::network_manager) fn veilid_quinn_client_endpoint(
    addr: SocketAddr,
) -> io::Result<quinn::Endpoint> {
    let socket = std::net::UdpSocket::bind(addr)?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        veilid_quinn_runtime(),
    )
}

#[expect(
    clippy::disallowed_methods,
    reason = "quinn's Runtime trait hands deadlines as Instant, so converting one needs the raw monotonic clock"
)]
fn raw_deadline(deadline: Instant) -> u64 {
    get_raw_timestamp()
        + deadline
            .saturating_duration_since(Instant::now())
            .as_micros() as u64
}

#[derive(Debug)]
struct VeilidQuinnRuntime;

impl Runtime for VeilidQuinnRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(VeilidQuinnTimer(sleep_until(raw_deadline(deadline))))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        spawn_detached("quinn driver", future);
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(VeilidQuinnUdpSocket::try_new(socket)?))
    }
}

#[derive(Debug)]
struct VeilidQuinnTimer(SleepUntil);

impl AsyncTimer for VeilidQuinnTimer {
    fn reset(mut self: Pin<&mut Self>, deadline: Instant) {
        self.0.reset(raw_deadline(deadline));
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Pin::new(&mut self.0).poll(cx)
    }
}

#[derive(Debug)]
struct VeilidQuinnUdpSocket {
    io: UdpSocketIo,
    state: UdpSocketState,
}

impl VeilidQuinnUdpSocket {
    fn try_new(socket: std::net::UdpSocket) -> io::Result<Self> {
        let state = UdpSocketState::new((&socket).into())?;
        Ok(Self {
            io: UdpSocketIo::from_std(socket)?,
            state,
        })
    }
}

impl AsyncUdpSocket for VeilidQuinnUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(UdpWritablePoller::new(move || {
            let socket = self.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.state.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(Interest::READABLE, || {
                self.state.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(res) => return Poll::Ready(Ok(res)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }
}

pub(in crate::network_manager) struct UdpWritablePoller<MakeFut> {
    make_fut: MakeFut,
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl<MakeFut, Fut> UdpWritablePoller<MakeFut>
where
    MakeFut: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<()>> + Send + Sync + 'static,
{
    pub fn new(make_fut: MakeFut) -> Self {
        Self {
            make_fut,
            fut: None,
        }
    }
}

impl<MakeFut> fmt::Debug for UdpWritablePoller<MakeFut> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpWritablePoller").finish_non_exhaustive()
    }
}

impl<MakeFut, Fut> UdpPoller for UdpWritablePoller<MakeFut>
where
    MakeFut: Fn() -> Fut + Send + Sync + Unpin + 'static,
    Fut: Future<Output = io::Result<()>> + Send + Sync + 'static,
{
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fut.is_none() {
            this.fut = Some(Box::pin((this.make_fut)()));
        }
        let result = this.fut.as_mut().unwrap().as_mut().poll(cx);
        if result.is_ready() {
            this.fut = None;
        }
        result
    }
}
