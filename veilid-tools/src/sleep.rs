use super::*;
use std::time::Duration;

cfg_if! {
    if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
        use async_executors::{Bindgen, Timer, YieldNow};

        type SleepUntilInner = PinBoxFutureStatic<()>;

        fn sleep_for(deadline: u64) -> SleepUntilInner {
            Bindgen.sleep(Duration::from_micros(deadline.saturating_sub(get_raw_timestamp())))
        }

        /// A sleep that completes at a deadline and can be rescheduled to a new one.
        ///
        /// Deadlines are microsecond timestamps in the domain of [`get_raw_timestamp`].
        ///
        /// It is [`Unpin`], so a caller holding one by value polls and resets it without
        /// pinning it first. A completed sleep must be reset before it is polled again, so
        /// that callers can treat it the same way on every target.
        pub struct SleepUntil {
            inner: SleepUntilInner,
            waker: Option<task::Waker>,
        }

        impl fmt::Debug for SleepUntil {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("SleepUntil").finish_non_exhaustive()
            }
        }

        impl SleepUntil {
            /// Reschedule the sleep to complete at `deadline` instead, waking a task that has
            /// already polled it so that it polls the new deadline.
            pub fn reset(&mut self, deadline: u64) {
                self.inner = sleep_for(deadline);
                if let Some(waker) = self.waker.take() {
                    waker.wake();
                }
            }
        }

        impl Future for SleepUntil {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<()> {
                let this = self.get_mut();
                this.waker = Some(cx.waker().clone());
                this.inner.as_mut().poll(cx)
            }
        }

        /// A [`SleepUntil`] that completes at `deadline`.
        #[must_use]
        pub fn sleep_until(deadline: u64) -> SleepUntil {
            SleepUntil {
                inner: sleep_for(deadline),
                waker: None,
            }
        }

        /// Suspend the current task for `millis` milliseconds; `0` yields once without sleeping.
        ///
        /// Abstracts over the async runtime (tokio, async-std, wasm).
        pub async fn sleep(millis: u32) {
            if millis == 0 {
                Bindgen.yield_now().await;
            } else {
                Bindgen.sleep(Duration::from_millis(millis.into())).await
            }
        }

    } else {
        use std::time::Instant;

        cfg_if! {
            if #[cfg(feature="rt-async-std")] {
                type SleepUntilInner = async_io::Timer;
            } else if #[cfg(feature="rt-tokio")] {
                /// Runtime timer behind [`SleepUntil`], boxed because `tokio::time::Sleep` is
                /// `!Unpin` and [`SleepUntil`] is `Unpin` on both runtimes.
                type SleepUntilInner = Pin<Box<tokio::time::Sleep>>;
            } else {
                compile_error!("needs executor implementation");
            }
        }

        #[expect(
            clippy::disallowed_methods,
            reason = "the runtime timers take an Instant deadline, so converting one needs the raw monotonic clock"
        )]
        fn deadline_instant(deadline: u64) -> Instant {
            Instant::now() + Duration::from_micros(deadline.saturating_sub(get_raw_timestamp()))
        }

        /// A sleep that completes at a deadline and can be rescheduled to a new one.
        ///
        /// Deadlines are microsecond timestamps in the domain of [`get_raw_timestamp`].
        ///
        /// It is [`Unpin`] on both runtimes, so a caller holding one by value polls and resets
        /// it without pinning it first. A completed sleep must be reset before it is polled
        /// again: the backends disagree on what a fired timer returns, async-io yielding
        /// `Pending` and tokio `Ready`.
        #[derive(Debug)]
        pub struct SleepUntil(SleepUntilInner);

        impl SleepUntil {
            /// Reschedule the sleep to complete at `deadline` instead, keeping any waker already
            /// registered with the runtime.
            pub fn reset(&mut self, deadline: u64) {
                let deadline = deadline_instant(deadline);
                cfg_if! {
                    if #[cfg(feature="rt-async-std")] {
                        self.0.set_at(deadline);
                    } else if #[cfg(feature="rt-tokio")] {
                        self.0.as_mut().reset(deadline.into());
                    } else {
                        compile_error!("needs executor implementation");
                    }
                }
            }
        }

        impl Future for SleepUntil {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<()> {
                cfg_if! {
                    if #[cfg(feature="rt-async-std")] {
                        Pin::new(&mut self.0).poll(cx).map(|_instant| ())
                    } else if #[cfg(feature="rt-tokio")] {
                        self.0.as_mut().poll(cx)
                    } else {
                        compile_error!("needs executor implementation");
                    }
                }
            }
        }

        /// A [`SleepUntil`] that completes at `deadline`.
        #[must_use]
        pub fn sleep_until(deadline: u64) -> SleepUntil {
            let deadline = deadline_instant(deadline);
            cfg_if! {
                if #[cfg(feature="rt-async-std")] {
                    SleepUntil(async_io::Timer::at(deadline))
                } else if #[cfg(feature="rt-tokio")] {
                    SleepUntil(Box::pin(tokio::time::sleep_until(deadline.into())))
                } else {
                    compile_error!("needs executor implementation");
                }
            }
        }

        /// Suspend the current task for `millis` milliseconds; `0` yields once without sleeping.
        ///
        /// Abstracts over the async runtime (tokio, async-std, wasm).
        pub async fn sleep(millis: u32) {
            if millis == 0 {
                cfg_if! {
                    if #[cfg(feature="rt-async-std")] {
                        async_std::task::yield_now().await;
                    } else if #[cfg(feature="rt-tokio")] {
                        tokio::task::yield_now().await;
                    }
                }
            } else {
                cfg_if! {
                    if #[cfg(feature="rt-async-std")] {
                        async_std::task::sleep(Duration::from_millis(u64::from(millis))).await;
                    } else if #[cfg(feature="rt-tokio")] {
                        tokio::time::sleep(Duration::from_millis(u64::from(millis))).await;
                    }
                }
            }
        }
    }
}
