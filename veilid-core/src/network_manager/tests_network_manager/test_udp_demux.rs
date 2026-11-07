use super::*;

use crate::network_manager::network::native::protocol::webtransport;
use crate::network_manager::network::native::udp_demux::demuxer::{
    demux_slot, DemuxerUdpSocket, KeptQuicBytes, MAX_DRAIN_BATCHES_PER_POLL,
    RAW_DEMUX_CHANNEL_DEPTH,
};
use crate::network_manager::network::native::udp_demux::{route_datagram, DatagramDestination};
use crate::network_manager::tests_network_manager::test_udp_protocol::assembly_buffer_frame;
use std::io::IoSliceMut;
use std::task::{Context, Poll, Wake, Waker};
use web_transport_quinn::quinn::{udp::RecvMeta, AsyncUdpSocket};

pub fn test_routes_quic_long_header_to_webtransport() {
    // Long header: form bit set; 0xC3 is a typical Initial first byte.
    assert_eq!(
        route_datagram(&[0xC3, 0, 0, 0, 1]),
        DatagramDestination::WebTransport
    );
    assert_eq!(route_datagram(&[0x80]), DatagramDestination::WebTransport);
}

pub fn test_routes_quic_short_header_to_webtransport() {
    // Short header (1-RTT): fixed bit set, form bit clear (0x40..=0x7F).
    assert_eq!(
        route_datagram(&[0x40, 1, 2, 3]),
        DatagramDestination::WebTransport
    );
    assert_eq!(
        route_datagram(&[0x5A, 9, 9]),
        DatagramDestination::WebTransport
    );
}

pub async fn test_routes_assembly_buffer_frame_to_raw_udp() {
    let framed = assembly_buffer_frame(b"hi").await;
    assert_eq!(framed[0], RAW_FIRST_BYTE);
    assert_eq!(route_datagram(&framed), DatagramDestination::RawUdp);
}

pub fn test_routes_empty_and_unclaimed_datagrams_to_raw_udp() {
    assert_eq!(route_datagram(&[]), DatagramDestination::RawUdp);
    assert_eq!(route_datagram(&[0x00]), DatagramDestination::RawUdp);
    assert_eq!(route_datagram(&[0x3F, 1, 2]), DatagramDestination::RawUdp);
}

pub fn test_no_first_byte_is_accepted_by_both_protocols() {
    for first_byte in 0u8..=0xFF {
        let datagram = [first_byte, 7, 7, 7];
        assert!(
            !(webtransport::accepts_datagram(&datagram) && AssemblyBuffer::is_frame(&datagram)),
            "first byte {first_byte:#04x} is accepted by both WebTransport and raw UDP"
        );
    }
}

/// A first byte with the QUIC long-header form bit set.
const QUIC_FIRST_BYTE: u8 = 0xC0;
const RAW_FIRST_BYTE: u8 = 1;

fn datagram(first: u8, fill: u8, len: usize) -> Vec<u8> {
    let mut d = vec![fill; len];
    d[0] = first;
    d
}

fn slot(datagrams: &[Vec<u8>]) -> (Vec<u8>, usize) {
    let mut buf: Vec<u8> = datagrams.concat();
    let len = buf.len();
    buf.resize(len + 128, 0xEE);
    (buf, len)
}

fn split(buf: &mut [u8], len: usize, stride: usize) -> (KeptQuicBytes, Vec<Vec<u8>>) {
    let mut forwarded = Vec::new();
    let kept = demux_slot(buf, len, stride, |d| forwarded.push(d.to_vec()));
    (kept, forwarded)
}

pub fn test_demux_slot_probe_bytes_route_as_expected() {
    assert_eq!(
        route_datagram(&[QUIC_FIRST_BYTE]),
        DatagramDestination::WebTransport
    );
    assert_eq!(
        route_datagram(&[RAW_FIRST_BYTE]),
        DatagramDestination::RawUdp
    );
}

pub fn test_demux_slot_keeps_a_single_quic_datagram() {
    let d = datagram(QUIC_FIRST_BYTE, 0xA1, 100);
    let (mut buf, len) = slot(std::slice::from_ref(&d));
    let (kept, forwarded) = split(&mut buf, len, 100);
    assert_eq!(kept.get(), 100);
    assert_eq!(&buf[..kept.get()], &d[..]);
    assert!(forwarded.is_empty());
}

pub fn test_demux_slot_forwards_a_single_raw_datagram() {
    let d = datagram(RAW_FIRST_BYTE, 0xB2, 100);
    let (mut buf, len) = slot(std::slice::from_ref(&d));
    let (kept, forwarded) = split(&mut buf, len, 100);
    assert_eq!(kept.get(), 0);
    assert_eq!(forwarded, vec![d]);
}

pub fn test_demux_slot_treats_zero_stride_as_one_datagram() {
    let q = datagram(QUIC_FIRST_BYTE, 0xC3, 300);
    let (mut buf, len) = slot(std::slice::from_ref(&q));
    let (kept, forwarded) = split(&mut buf, len, 0);
    assert_eq!(kept.get(), 300);
    assert_eq!(&buf[..kept.get()], &q[..]);
    assert!(forwarded.is_empty());

    let r = datagram(RAW_FIRST_BYTE, 0xD4, 300);
    let (mut buf, len) = slot(std::slice::from_ref(&r));
    let (kept, forwarded) = split(&mut buf, len, 0);
    assert_eq!(kept.get(), 0);
    assert_eq!(forwarded, vec![r]);
}

pub fn test_demux_slot_handles_stride_larger_than_len() {
    let r = datagram(RAW_FIRST_BYTE, 0xE5, 40);
    let (mut buf, len) = slot(std::slice::from_ref(&r));
    let (kept, forwarded) = split(&mut buf, len, 1200);
    assert_eq!(kept.get(), 0);
    assert_eq!(forwarded, vec![r]);
}

pub fn test_demux_slot_keeps_an_all_quic_train() {
    let ds: Vec<Vec<u8>> = (0..5)
        .map(|i| datagram(QUIC_FIRST_BYTE, 0x10 + i as u8, 50))
        .collect();
    let (mut buf, len) = slot(&ds);
    let (kept, forwarded) = split(&mut buf, len, 50);
    assert_eq!(kept.get(), len);
    assert_eq!(&buf[..kept.get()], &ds.concat()[..]);
    assert!(forwarded.is_empty());
}

pub fn test_demux_slot_forwards_an_all_raw_train() {
    let ds: Vec<Vec<u8>> = (0..5)
        .map(|i| datagram(RAW_FIRST_BYTE, 0x20 + i as u8, 50))
        .collect();
    let (mut buf, len) = slot(&ds);
    let (kept, forwarded) = split(&mut buf, len, 50);
    assert_eq!(kept.get(), 0);
    assert_eq!(forwarded, ds);
}

pub fn test_demux_slot_splits_an_alternating_train() {
    let ds: Vec<Vec<u8>> = (0..6)
        .map(|i| {
            let first = if i % 2 == 0 {
                QUIC_FIRST_BYTE
            } else {
                RAW_FIRST_BYTE
            };
            datagram(first, 0x30 + i as u8, 64)
        })
        .collect();
    let (mut buf, len) = slot(&ds);
    let (kept, forwarded) = split(&mut buf, len, 64);

    let expected_quic: Vec<Vec<u8>> = ds.iter().step_by(2).cloned().collect();
    let expected_raw: Vec<Vec<u8>> = ds.iter().skip(1).step_by(2).cloned().collect();
    assert_eq!(kept.get(), expected_quic.len() * 64);
    assert_eq!(&buf[..kept.get()], &expected_quic.concat()[..]);
    assert_eq!(forwarded, expected_raw);
    assert!(buf[len..].iter().all(|&b| b == 0xEE));
}

pub fn test_demux_slot_keeps_a_short_final_quic_datagram() {
    let ds = vec![
        datagram(RAW_FIRST_BYTE, 0x41, 64),
        datagram(QUIC_FIRST_BYTE, 0x42, 64),
        datagram(QUIC_FIRST_BYTE, 0x43, 20),
    ];
    let (mut buf, len) = slot(&ds);
    let (kept, forwarded) = split(&mut buf, len, 64);
    assert_eq!(kept.get(), 64 + 20);
    assert_eq!(
        &buf[..kept.get()],
        &[ds[1].clone(), ds[2].clone()].concat()[..]
    );
    assert_eq!(forwarded, vec![ds[0].clone()]);
}

pub fn test_demux_slot_forwards_a_short_final_raw_datagram() {
    let ds = vec![
        datagram(QUIC_FIRST_BYTE, 0x51, 64),
        datagram(RAW_FIRST_BYTE, 0x52, 64),
        datagram(RAW_FIRST_BYTE, 0x53, 20),
    ];
    let (mut buf, len) = slot(&ds);
    let (kept, forwarded) = split(&mut buf, len, 64);
    assert_eq!(kept.get(), 64);
    assert_eq!(&buf[..kept.get()], &ds[0][..]);
    assert_eq!(forwarded, vec![ds[1].clone(), ds[2].clone()]);
}

pub fn test_retained_prefix_reframes_into_the_original_quic_datagrams() {
    let ds = vec![
        datagram(RAW_FIRST_BYTE, 0x61, 64),
        datagram(QUIC_FIRST_BYTE, 0x62, 64),
        datagram(RAW_FIRST_BYTE, 0x63, 64),
        datagram(QUIC_FIRST_BYTE, 0x64, 64),
        datagram(RAW_FIRST_BYTE, 0x65, 64),
        datagram(QUIC_FIRST_BYTE, 0x66, 30),
    ];
    let (mut buf, len) = slot(&ds);
    let (kept, _forwarded) = split(&mut buf, len, 64);

    let reframed: Vec<Vec<u8>> = buf[..kept.get()].chunks(64).map(|c| c.to_vec()).collect();
    assert_eq!(
        reframed,
        vec![ds[1].clone(), ds[3].clone(), ds[5].clone()],
        "quinn's stride-chunk re-framing must reproduce the QUIC datagrams"
    );
}

pub fn test_raw_demux_channel_is_bounded() {
    let io = Arc::new(
        bind_udp_socket_io("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .unwrap(),
    );
    let (_socket, rx) = DemuxerUdpSocket::try_new(io, None).unwrap();
    assert_eq!(rx.capacity(), Some(RAW_DEMUX_CHANNEL_DEPTH));
}

/// The wake reaches the task by a different route on each runtime. Under tokio the
/// socket's readiness is cached, so a poll reaches the drain cap and self-wakes.
/// Under async-io a readiness event is consumed by the poll that reports it, so a
/// poll yields after one batch and the reactor re-arms and wakes the task instead.
/// The loop below therefore polls until datagrams appear rather than assuming one
/// poll forwards any.
pub async fn test_poll_recv_yields_under_raw_flood() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingWaker(AtomicUsize);
    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    const BUFS: usize = 4;

    let server = Arc::new(
        bind_udp_socket_io("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();
    let (socket, rx) = DemuxerUdpSocket::try_new(server, None).unwrap();

    let cap_drain = MAX_DRAIN_BATCHES_PER_POLL * BUFS * socket.max_receive_segments();
    let flood = cap_drain * 4;

    let client = bind_udp_socket_io("127.0.0.1:0".parse().unwrap())
        .unwrap()
        .unwrap();
    let raw = [RAW_FIRST_BYTE, 2, 3, 4];
    for _ in 0..flood {
        client.send_to(&raw, server_addr).await.unwrap();
    }
    sleep(150).await;

    let mut storage: Vec<Vec<u8>> = (0..BUFS).map(|_| vec![0u8; 2048]).collect();
    let mut bufs: Vec<IoSliceMut<'_>> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut meta = vec![RecvMeta::default(); BUFS];

    let waker = Arc::new(CountingWaker(AtomicUsize::new(0)));
    let w: Waker = waker.clone().into();
    let mut cx = Context::from_waker(&w);

    let mut drained = 0usize;
    for _ in 0..16 {
        let poll = socket.poll_recv(&mut cx, &mut bufs, &mut meta);
        assert!(
            matches!(poll, Poll::Pending),
            "a raw flood exceeding the drain cap must yield Poll::Pending, got {poll:?}"
        );

        let now = rx.len();
        assert!(
            now - drained <= cap_drain,
            "one poll drained {} datagrams, exceeding the cap of {cap_drain}",
            now - drained
        );
        drained = now;
        if drained > 0 {
            break;
        }
        sleep(50).await;
    }

    assert!(
        waker.0.load(Ordering::SeqCst) >= 1,
        "the yield must wake the task so draining resumes"
    );
    assert!(
        drained > 0,
        "poll_recv should have forwarded some raw datagrams"
    );
    assert!(
        drained < flood,
        "the drain cap must leave datagrams queued, but all {flood} were drained in one poll"
    );
}

/// Segmentation on send and coalescing on receive are both optional kernel features
/// that a sandbox may refuse, so every step that cannot be arranged here returns
/// early instead of failing.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub async fn test_coalesced_slot_is_split_per_datagram() {
    use veilid_tools::Interest;
    use web_transport_quinn::quinn::udp::{Transmit, UdpSocketState};

    const SEGMENT_LEN: usize = 64;
    const SEGMENTS: usize = 6;
    const BUFS: usize = 4;

    let server = Arc::new(
        bind_udp_socket_io("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();
    let (socket, rx) = DemuxerUdpSocket::try_new(server, None).unwrap();
    let segments = socket.max_receive_segments();
    if segments < SEGMENTS {
        return;
    }

    let client = bind_udp_socket_io("127.0.0.1:0".parse().unwrap())
        .unwrap()
        .unwrap();
    let Ok(client_state) = UdpSocketState::new((&client).into()) else {
        return;
    };
    if client_state.max_gso_segments() < SEGMENTS {
        return;
    }

    let mut train = Vec::with_capacity(SEGMENT_LEN * SEGMENTS);
    let mut expected_quic: Vec<Vec<u8>> = Vec::new();
    let mut expected_raw: Vec<Vec<u8>> = Vec::new();
    for i in 0..SEGMENTS {
        let quic = i % 2 == 0;
        let first = if quic {
            QUIC_FIRST_BYTE
        } else {
            RAW_FIRST_BYTE
        };
        let d = datagram(first, 0x70 + i as u8, SEGMENT_LEN);
        train.extend_from_slice(&d);
        if quic {
            expected_quic.push(d);
        } else {
            expected_raw.push(d);
        }
    }

    let transmit = Transmit {
        destination: server_addr,
        ecn: None,
        contents: &train,
        segment_size: Some(SEGMENT_LEN),
        src_ip: None,
    };
    if client.writable().await.is_err()
        || client
            .try_io(Interest::WRITABLE, || {
                client_state.send((&client).into(), &transmit)
            })
            .is_err()
    {
        return;
    }
    sleep(150).await;

    let mut storage: Vec<Vec<u8>> = (0..BUFS)
        .map(|_| vec![0u8; SEGMENT_LEN * segments])
        .collect();
    let mut bufs: Vec<IoSliceMut<'_>> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut meta = vec![RecvMeta::default(); BUFS];
    let mut cx = Context::from_waker(Waker::noop());

    let mut quic_out: Vec<Vec<u8>> = Vec::new();
    let mut coalesced = false;
    let mut pending_polls = 0usize;
    while quic_out.len() < expected_quic.len() {
        // A runtime that consumes a readiness event in the poll that reports it needs its
        // reactor to re-arm between polls, so a Pending here means retry, not end of train.
        let Poll::Ready(Ok(n)) = socket.poll_recv(&mut cx, &mut bufs, &mut meta) else {
            pending_polls += 1;
            if pending_polls > 16 {
                break;
            }
            sleep(50).await;
            continue;
        };
        for slot in 0..n {
            let (len, stride) = (meta[slot].len, meta[slot].stride);
            if stride == 0 {
                return;
            }
            coalesced |= len > stride;
            for chunk in bufs[slot][..len].chunks(stride) {
                quic_out.push(chunk.to_vec());
            }
        }
    }

    if !coalesced {
        return;
    }
    assert_eq!(
        quic_out, expected_quic,
        "the QUIC datagrams of a coalesced train must survive the split intact"
    );
    let raw_out: Vec<Vec<u8>> = rx.drain().map(|(_addr, d)| d).collect();
    assert_eq!(
        raw_out, expected_raw,
        "the raw datagrams of a coalesced train must be forwarded one by one"
    );
}
