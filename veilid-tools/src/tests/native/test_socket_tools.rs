use crate::*;

cfg_if! {
    if #[cfg(feature="rt-async-std")] {
        use async_std::net::{TcpListener, TcpStream};
    } else if #[cfg(feature="rt-tokio")] {
        use tokio::net::{TcpListener, TcpStream};
    }
}

/// Linger and other option changes reach the socket through a borrowed view that never
/// closes it, so the stream stays usable afterwards
pub async fn test_borrowed_socket_operations() {
    info!("-- test_borrowed_socket_operations");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener bind");
    let addr = listener.local_addr().expect("local addr");
    let (client, server) =
        futures_util::future::join(TcpStream::connect(addr), listener.accept()).await;
    let client = client.expect("connect");
    let (_server, _) = server.expect("accept");

    set_tcp_stream_linger(&client, Some(core::time::Duration::from_secs(0))).expect("linger on");
    let linger = socket2_operation(&client, |s| s.linger()).expect("read linger");
    assert_eq!(linger, Some(core::time::Duration::from_secs(0)));
    set_tcp_stream_linger(&client, None).expect("linger off");
    assert_eq!(
        socket2_operation(&client, |s| s.linger()).expect("read linger"),
        None
    );

    // The stream still works, so nothing above closed its descriptor
    assert!(client.local_addr().is_ok());
    assert!(client.peer_addr().is_ok());
}

pub async fn test_all() {
    test_borrowed_socket_operations().await;
}
