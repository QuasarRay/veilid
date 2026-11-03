use super::*;
use crate::network_manager::network::native::protocol::udp::RawUdpProtocolHandler;
use crate::network_manager::network::native::NativeNetworkTimings;
use crate::tests::*;
use std::net::{Ipv4Addr, SocketAddr};

/// One frame of `payload`, produced by `AssemblyBuffer` rather than written out by hand.
pub async fn assembly_buffer_frame(payload: &[u8]) -> Vec<u8> {
    let (tx, rx) = flume::unbounded();
    let sent = AssemblyBuffer::new()
        .split_message(
            Bytes::copy_from_slice(payload),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1),
            SAFE_TRANSPORT_MTU.into(),
            |frame: Bytes, _remote_addr| {
                let tx = tx.clone();
                async move {
                    tx.send_async(frame).await.expect("should send");
                    Ok(NetworkResult::value(()))
                }
            },
        )
        .await;
    assert!(
        matches!(sent, Ok(NetworkResult::Value(()))),
        "should frame the message"
    );
    rx.try_recv().expect("should produce a frame").to_vec()
}

pub async fn test_demuxed_recv_reassembles_from_channel() {
    let registry = mock_registry::init("udp_demuxed_recv").await;

    let socket = Arc::new(
        bind_udp_socket_io(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .unwrap()
            .unwrap(),
    );
    let (tx, rx) = flume::unbounded();
    let timings = NativeNetworkTimings::new(&registry.config());
    let handler = RawUdpProtocolHandler::new_demuxed(registry.clone(), socket, rx, &timings);

    let remote = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 7).into(), 4242);
    let frame = assembly_buffer_frame(b"hello demux").await;
    let frame_len = u16::try_from(frame.len()).unwrap();
    tx.send((remote, frame)).unwrap();

    let mut buf = vec![0u8; 65536];
    let (size, flow, opt_datagram_len) = handler.recv_message(&mut buf).await.unwrap();
    assert_eq!(&buf[..size], b"hello demux");
    assert_eq!(
        opt_datagram_len,
        Some(frame_len),
        "a whole-message frame reports the datagram it came in, as on a socket read"
    );
    assert_eq!(flow.remote_address().socket_addr(), remote);
    assert_eq!(flow.protocol_type(), ProtocolType::UDP);

    mock_registry::terminate(registry).await;
}
