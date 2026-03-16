use super::*;

pub async fn yielding<R, T: FnOnce() -> R>(x: T) -> R {
    let out = x();
    sleep(0).await;
    out
}

cfg_if! {
    if #[cfg(feature="rt-wasm-bindgen")] {
        use async_executors::{Bindgen, LocalSpawnHandleExt, SpawnHandleExt};

        cfg_if! {
            if #[cfg(feature="debug-locks-detect")] {
                use std::task::{Context, Poll, Wake, Waker};
                use std::sync::{atomic::AtomicU64, LazyLock};
                use send_wrapper::SendWrapper;

                static ACTIVE_TASK_ID: LazyLock<SendWrapper<AtomicU64>> = LazyLock::new(|| SendWrapper::new(AtomicU64::new(0)));
                static NEXT_TASK_ID: LazyLock<SendWrapper<AtomicU64>> = LazyLock::new(|| SendWrapper::new(AtomicU64::new(0)));

                #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
                pub struct AsyncTaskId(u64);
                impl AsyncTaskId {
                    #[must_use]
                    pub fn this() -> AsyncTaskId {
                        AsyncTaskId(ACTIVE_TASK_ID.load(Ordering::Relaxed))
                    }
                }

                // Wrapper for waker that propagates a task id
                struct AllocTaskIdWakerWrapper {
                    inner_waker: Waker,
                    task_id: u64,
                }
                impl<'a> Wake for AllocTaskIdWakerWrapper {
                    fn wake(self: Arc<Self>) {
                        ACTIVE_TASK_ID.store(self.task_id, Ordering::Relaxed);
                        self.inner_waker.wake_by_ref();
                    }
                }

                // Wrapper that adds a task id to the context of a future that is the start of a spawned task
                struct AllocTaskIdFuture<Fut: Future> {
                    inner: Fut,
                    task_id: u64,
                }
                impl<Fut: Future> From<Fut> for AllocTaskIdFuture<Fut> {
                    fn from(inner: Fut) -> Self {
                        let task_id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
                        Self {
                            inner,
                            task_id,
                        }
                    }
                }
                impl<Fut: Future> Future for AllocTaskIdFuture<Fut> {
                    type Output = Fut::Output;
                    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                        // Poll inner future
                        let task_id = self.task_id;
                        let inner_fut = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
                        let wrapped_waker = Arc::new(AllocTaskIdWakerWrapper {
                            inner_waker: cx.waker().clone(),
                            task_id,
                        }).into();
                        let mut wrapped_cx = Context::from_waker(&wrapped_waker);
                        inner_fut.poll(&mut wrapped_cx)
                    }
                }
            }
        }

        pub fn spawn<Out>(_name: &str, future: impl Future<Output = Out> + Send + 'static) -> MustJoinHandle<Out>
        where
            Out: Send + 'static,
        {

            #[cfg(feature="debug-locks-detect")]
            let future = AllocTaskIdFuture::from(future);

            MustJoinHandle::new(
                Bindgen
                    .spawn_handle(future)
                    .expect_or_log("wasm-bindgen-futures spawn_handle_local should never error out"),
            )
        }

        pub fn spawn_local<Out>(_name: &str, future: impl Future<Output = Out> + 'static) -> MustJoinHandle<Out>
        where
            Out: 'static,
        {

            #[cfg(feature="debug-locks-detect")]
            let future = AllocTaskIdFuture::from(future);

            MustJoinHandle::new(
                Bindgen
                    .spawn_handle_local(future)
                    .expect_or_log("wasm-bindgen-futures spawn_handle_local should never error out"),
            )
        }

        pub fn spawn_detached<Out>(_name: &str, future: impl Future<Output = Out> + Send + 'static)
        where
            Out: Send + 'static,
        {
            #[cfg(feature="debug-locks-detect")]
            let future = AllocTaskIdFuture::from(future);

            Bindgen
                .spawn_handle_local(future)
                .expect_or_log("wasm-bindgen-futures spawn_handle_local should never error out")
                .detach()
        }
        pub fn spawn_detached_local<Out>(_name: &str, future: impl Future<Output = Out> + 'static)
        where
            Out: 'static,
        {
            #[cfg(feature="debug-locks-detect")]
            let future = AllocTaskIdFuture::from(future);

            Bindgen
                .spawn_handle_local(future)
                .expect_or_log("wasm-bindgen-futures spawn_handle_local should never error out")
                .detach()
        }

        /// For things that use locks or IO operations or cpu tasks that take between 10-100us
        /// WASM version is a stub that just uses a yield point
        pub async fn blocking_yielding<R: Send + 'static>(x: impl FnOnce() -> R + Send + 'static) -> R {
            yielding(x).await
        }

        /// For heavy cpu-intensive tasks that do not use locks or IO operations > (100us)
        /// WASM version is a stub that just uses a yield point
        pub async fn cpu_yielding<R: Send + 'static>(x: impl FnOnce() -> R + Send + 'static) -> R {
            yielding(x).await
        }

        /// Yielding that chooses the best mechanism using a scaled approach
        pub async fn scaled_yielding<
            N: PartialOrd,
            R: Send + 'static,
            T: FnOnce() -> R + Send + 'static,
        >(
            _n: N,
            _yield_n: N,
            _cpu_n: N,
            x: T,
        ) -> R {
            // Due to speed issues and an inability to spawn in the WASM target, always yield
            yielding(x).await
        }

    } else {

        pub fn spawn<Out>(name: &str, future: impl Future<Output = Out> + Send + 'static) -> MustJoinHandle<Out>
        where
            Out: Send + 'static,
        {
            cfg_if! {
                if #[cfg(feature="rt-async-std")] {
                    MustJoinHandle::new(async_std::task::Builder::new().name(name.to_string()).spawn(future).unwrap_or_log())
                } else if #[cfg(all(tokio_unstable, feature="rt-tokio", feature="tracing"))] {
                    MustJoinHandle::new(tokio::task::Builder::new().name(name).spawn(future).unwrap_or_log())
                } else if #[cfg(feature="rt-tokio")] {
                    let _name = name;
                    MustJoinHandle::new(tokio::task::spawn(future))
                }
            }
        }

        pub fn spawn_local<Out>(name: &str, future: impl Future<Output = Out> + 'static) -> MustJoinHandle<Out>
        where
            Out: 'static,
        {
            cfg_if! {
                if #[cfg(feature="rt-async-std")] {
                    MustJoinHandle::new(async_std::task::Builder::new().name(name.to_string()).local(future).unwrap_or_log())
                } else if #[cfg(all(tokio_unstable, feature="rt-tokio", feature="tracing"))] {
                    MustJoinHandle::new(tokio::task::Builder::new().name(name).spawn_local(future).unwrap_or_log())
                } else if #[cfg(feature="rt-tokio")] {
                    let _name = name;
                    MustJoinHandle::new(tokio::task::spawn_local(future))
                }
            }
        }

        pub fn spawn_detached<Out>(name: &str, future: impl Future<Output = Out> + Send + 'static)
        where
            Out: Send + 'static,
        {
            cfg_if! {
                if #[cfg(feature="rt-async-std")] {
                    drop(async_std::task::Builder::new().name(name.to_string()).spawn(future).unwrap_or_log());
                } else if #[cfg(all(tokio_unstable, feature="rt-tokio", feature="tracing"))] {
                    drop(tokio::task::Builder::new().name(name).spawn(future).unwrap_or_log());
                } else if #[cfg(feature="rt-tokio")] {
                    let _name = name;
                    drop(tokio::task::spawn(future))
                }
            }
        }

        pub fn spawn_detached_local<Out>(name: &str,future: impl Future<Output = Out> + 'static)
        where
            Out: 'static,
        {
            cfg_if! {
                if #[cfg(feature="rt-async-std")] {
                    drop(async_std::task::Builder::new().name(name.to_string()).local(future).unwrap_or_log());
                } else if #[cfg(all(tokio_unstable, feature="rt-tokio", feature="tracing"))] {
                    drop(tokio::task::Builder::new().name(name).spawn_local(future).unwrap_or_log());
                } else if #[cfg(feature="rt-tokio")] {
                    let _name = name;
                    drop(tokio::task::spawn_local(future))
                }
            }
        }

        pub async fn blocking_wrapper<F, R>(blocking_task: F) -> R
        where
            F: FnOnce() -> R + Send + 'static,
            R: Send + 'static,
        {
            // run blocking stuff in blocking thread
            cfg_if! {
                if #[cfg(feature="rt-async-std")] {
                    async_std::task::spawn_blocking(blocking_task).await
                } else if #[cfg(feature="rt-tokio")] {
                    tokio::task::spawn_blocking(blocking_task).await.unwrap_or_log()
                } else {
                    #[compile_error("must use an executor")]
                }
            }
        }

        /// For things that use locks or IO operations or cpu tasks that take between 10-100us
        pub async fn blocking_yielding<R: Send + 'static>(x: impl FnOnce() -> R + Send + 'static) -> R
        {
            blocking_wrapper(x).await
        }

        /// For heavy cpu-intensive tasks that do not use locks or IO operations > (100us)
        pub async fn cpu_yielding<R: Send + 'static>(x: impl FnOnce() -> R + Send + 'static) -> R {
            let (tx, rx) = flume::bounded(1);
            rayon::spawn_fifo(move || {
                let result = x();
                let _ = tx.send(result);
            });
            rx.recv_async().await.unwrap_or_log()
        }

        /// Yielding that chooses the best mechanism using a scaled approach
        pub async fn scaled_yielding<
            N: PartialOrd,
            R: Send + 'static,
            T: FnOnce() -> R + Send + 'static,
            >(
            n: N,
            yield_n: N,
            cpu_n: N,
            x: T,
            ) -> R {
            if n < yield_n {
                x()
            } else if n < cpu_n {
                yielding(x).await
            } else {
                cpu_yielding(x).await
            }
        }

        cfg_if! {
            if #[cfg(feature="rt-tokio")] {
                #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
                pub struct AsyncTaskId(tokio::task::Id);
                impl AsyncTaskId {
                    #[must_use]
                    pub fn this() -> AsyncTaskId {
                        AsyncTaskId(tokio::task::id())
                    }
                }
            } else if #[cfg(feature="rt-async-std")] {
                #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
                pub struct AsyncTaskId(async_std::task::TaskId);
                impl AsyncTaskId {
                    #[must_use]
                    pub fn this() -> AsyncTaskId {
                        AsyncTaskId(async_std::task::current().id())
                    }
                }
            } else {
                #[compile_error("must use an executor")]
            }
        }
    }
}
