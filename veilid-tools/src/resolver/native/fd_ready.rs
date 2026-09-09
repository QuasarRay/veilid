//! Readiness wait on a file descriptor the platform resolver owns.

use super::*;
use dns::DnsError;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

/// Borrows the fd for the reactor without ever closing it; the caller owns the lifetime
struct FdHandle(RawFd);

impl AsRawFd for FdHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl AsFd for FdHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: the fd stays open for this wrapper's lifetime; the owner closes it only after
        // the reactor registration has been dropped
        unsafe { BorrowedFd::borrow_raw(self.0) }
    }
}

/// Park until `fd` is readable, deregistering before the caller closes it
pub(crate) async fn wait_readable(fd: RawFd) -> Result<(), DnsError> {
    cfg_if! {
        if #[cfg(feature="rt-tokio")] {
            let async_fd = tokio::io::unix::AsyncFd::with_interest(
                FdHandle(fd),
                tokio::io::Interest::READABLE,
            )?;
            let _guard = async_fd.readable().await?;
            Ok(())
        } else if #[cfg(feature="rt-async-std")] {
            // new_nonblocking: the fd is the resolver's, so O_NONBLOCK is not ours to set
            let async_fd = async_io::Async::new_nonblocking(FdHandle(fd))?;
            async_fd.readable().await?;
            Ok(())
        } else {
            compile_error!("needs executor implementation");
        }
    }
}
