use super::protocol::webtransport;
use veilid_tools::AssemblyBuffer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::network_manager) enum DatagramDestination {
    WebTransport,
    RawUdp,
}

type AcceptsDatagram = fn(&[u8]) -> bool;

const SHARED_UDP_PORT_PROTOCOLS: [(AcceptsDatagram, DatagramDestination); 2] = [
    (
        webtransport::accepts_datagram,
        DatagramDestination::WebTransport,
    ),
    (AssemblyBuffer::is_frame, DatagramDestination::RawUdp),
];

pub(in crate::network_manager) fn route_datagram(datagram: &[u8]) -> DatagramDestination {
    for (accepts, destination) in SHARED_UDP_PORT_PROTOCOLS {
        if accepts(datagram) {
            return destination;
        }
    }
    DatagramDestination::RawUdp
}

pub(in crate::network_manager) use demuxer::DemuxerUdpSocket;

pub(in crate::network_manager) mod demuxer {
    use super::super::webtransport_quinn_runtime::UdpWritablePoller;
    use super::{route_datagram, DatagramDestination};
    use crate::network_manager::network::native::protocol::udp::DemuxedDatagram;
    use std::fmt;
    use std::io::{self, IoSliceMut};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{ready, Context, Poll};
    use veilid_tools::{keep_udp_fragmentation_options, Interest, UdpSocketIo};
    use web_transport_quinn::quinn::{
        udp::{RecvMeta, Transmit, UdpSocketState, BATCH_SIZE},
        AsyncUdpSocket, UdpPoller,
    };

    // The kernel coalesces at most UDP_GRO_CNT_MAX datagrams into one receive slot, defined as 64
    // in net/ipv4/udp_offload.c, and quinn-udp reports that same 64 from `gro_segments()` once it
    // turns UDP_GRO on.
    const MAX_GRO_SEGMENTS_PER_SLOT: usize = 64;

    pub(in crate::network_manager) const MAX_DRAIN_BATCHES_PER_POLL: usize = 2;

    pub(in crate::network_manager) const RAW_DEMUX_CHANNEL_DEPTH: usize =
        BATCH_SIZE * MAX_GRO_SEGMENTS_PER_SLOT * MAX_DRAIN_BATCHES_PER_POLL;

    /// Bytes of QUIC data that demuxing compacted to the front of a receive slot.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::network_manager) struct KeptQuicBytes(usize);

    impl KeptQuicBytes {
        pub fn get(self) -> usize {
            self.0
        }

        pub fn is_empty(self) -> bool {
            self.0 == 0
        }
    }

    // quinn's endpoint driver polls `poll_recv` until it returns `Pending`, so waking before
    // yielding keeps the task scheduled and draining resumes on the next poll rather than
    // waiting for fresh socket readiness.
    fn wake_and_yield<T>(cx: &Context) -> Poll<T> {
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    pub(in crate::network_manager) fn demux_slot(
        buf: &mut [u8],
        len: usize,
        stride: usize,
        mut forward: impl FnMut(&[u8]),
    ) -> KeptQuicBytes {
        if stride == 0 || len <= stride {
            return match route_datagram(&buf[..len]) {
                DatagramDestination::WebTransport => KeptQuicBytes(len),
                DatagramDestination::RawUdp => {
                    forward(&buf[..len]);
                    KeptQuicBytes(0)
                }
            };
        }

        let mut kept = 0usize;
        let mut offset = 0usize;
        while offset < len {
            // Only the final segment of a train may be shorter than the stride.
            let end = offset + stride.min(len - offset);
            match route_datagram(&buf[offset..end]) {
                DatagramDestination::WebTransport => {
                    if kept != offset {
                        buf.copy_within(offset..end, kept);
                    }
                    kept += end - offset;
                }
                DatagramDestination::RawUdp => {
                    forward(&buf[offset..end]);
                }
            }
            offset = end;
        }
        KeptQuicBytes(kept)
    }

    pub(in crate::network_manager) struct DemuxerUdpSocket {
        io: Arc<UdpSocketIo>,
        state: UdpSocketState,
        raw_tx: flume::Sender<DemuxedDatagram>,
    }

    impl fmt::Debug for DemuxerUdpSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("DemuxerUdpSocket")
                .field("local_addr", &self.io.local_addr().ok())
                .finish_non_exhaustive()
        }
    }

    impl DemuxerUdpSocket {
        pub fn try_new(
            io: Arc<UdpSocketIo>,
        ) -> io::Result<(Arc<Self>, flume::Receiver<DemuxedDatagram>)> {
            // quinn-udp forbids fragmentation, so put back the builder's policy for raw veilid UDP
            let state = keep_udp_fragmentation_options(&io, || UdpSocketState::new((&*io).into()))?;
            let (raw_tx, rx) = flume::bounded(RAW_DEMUX_CHANNEL_DEPTH);
            let socket = Arc::new(Self { io, state, raw_tx });
            Ok((socket, rx))
        }
    }

    impl AsyncUdpSocket for DemuxerUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(UdpWritablePoller::new(move || {
                let socket = self.clone();
                async move { socket.io.writable().await }
            }))
        }

        fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
            self.io.try_io(Interest::WRITABLE, || {
                self.state.send((&*self.io).into(), transmit)
            })
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            for _ in 0..MAX_DRAIN_BATCHES_PER_POLL {
                ready!(self.io.poll_recv_ready(cx))?;
                let res = match self.io.try_io(Interest::READABLE, || {
                    self.state.recv((&*self.io).into(), bufs, meta)
                }) {
                    Ok(res) => res,
                    // Spurious readiness; poll again.
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Poll::Ready(Err(e)),
                };

                let mut write = 0usize;
                for i in 0..res {
                    let len = meta[i].len;
                    let stride = meta[i].stride;
                    let addr = meta[i].addr;
                    let kept = demux_slot(&mut bufs[i], len, stride, |datagram| {
                        let _ = self.raw_tx.try_send((addr, datagram.to_vec()));
                    });

                    // quinn re-frames the slot in `stride`-sized chunks, and compaction keeps
                    // the retained bytes in order so the only short segment is still last;
                    // `stride` therefore stays as the kernel reported it.
                    meta[i].len = kept.get();
                    if !kept.is_empty() {
                        if write != i {
                            bufs.swap(write, i);
                            meta.swap(write, i);
                        }
                        write += 1;
                    }
                }

                if write > 0 {
                    return Poll::Ready(Ok(write));
                }
            }
            wake_and_yield(cx)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.io.local_addr()
        }

        fn max_transmit_segments(&self) -> usize {
            self.state.max_gso_segments()
        }

        // quinn-udp turns UDP_GRO on when it wraps the socket and offers no way to turn it
        // back off, so the kernel can coalesce up to `gro_segments()` datagrams into one slot
        // and reporting a smaller number would let it truncate the train.
        fn max_receive_segments(&self) -> usize {
            self.state.gro_segments()
        }

        // Datagrams on this socket may fragment, so a path MTU probe could pass in pieces, and
        // quinn keeps the shared endpoint at its initial MTU instead of probing
        fn may_fragment(&self) -> bool {
            true
        }
    }
}
