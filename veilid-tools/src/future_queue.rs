use super::*;
use futures_util::{Stream, StreamExt as _};
use stop_token::future::FutureExt as _;

/// Returns true if the future queue was processed to completion, false if the stop token was triggered
pub async fn process_batched_future_queue_result<I, C, E, R>(
    future_queue: I,
    batch_size: usize,
    stop_token: StopToken,
    result_callback: C,
) -> Result<bool, E>
where
    I: IntoIterator,
    C: Fn(R) -> Result<(), E>,
    <I as std::iter::IntoIterator>::Item: core::future::Future<Output = R>,
{
    let mut buffered_futures =
        futures_util::stream::iter(future_queue).buffer_unordered(batch_size);
    loop {
        let res = buffered_futures.next().timeout_at(stop_token.clone()).await;
        match res {
            Ok(Some(res)) => {
                result_callback(res)?;
            }
            Ok(None) => {
                break Ok(true);
            }
            Err(_) => {
                break Ok(false);
            }
        }
    }
}

pub async fn process_batched_future_queue_void<I>(
    future_queue: I,
    batch_size: usize,
    stop_token: StopToken,
) -> bool
where
    I: IntoIterator,
    <I as std::iter::IntoIterator>::Item: core::future::Future<Output = ()>,
{
    let mut buffered_futures =
        futures_util::stream::iter(future_queue).buffer_unordered(batch_size);
    loop {
        let res = buffered_futures.next().timeout_at(stop_token.clone()).await;
        match res {
            Ok(Some(())) => {
                // Do nothing
            }
            Ok(None) => {
                break true;
            }
            Err(_) => {
                break false;
            }
        }
    }
}

pub async fn process_batched_future_stream_result<S, C, E, R>(
    future_stream: S,
    batch_size: usize,
    stop_token: StopToken,
    result_callback: C,
) -> Result<bool, E>
where
    S: Stream,
    C: Fn(R) -> Result<(), E>,
    <S as Stream>::Item: core::future::Future<Output = R>,
{
    let mut buffered_futures = Box::pin(future_stream.buffer_unordered(batch_size));
    loop {
        let res = buffered_futures.next().timeout_at(stop_token.clone()).await;
        match res {
            Ok(Some(res)) => {
                result_callback(res)?;
            }
            Ok(None) => {
                break Ok(true);
            }
            Err(_) => {
                break Ok(false);
            }
        }
    }
}

pub async fn process_batched_future_stream_void<S>(
    future_stream: S,
    batch_size: usize,
    stop_token: StopToken,
) -> bool
where
    S: Stream,
    <S as Stream>::Item: core::future::Future<Output = ()>,
{
    let mut buffered_futures = Box::pin(future_stream.buffer_unordered(batch_size));
    loop {
        let res = buffered_futures.next().timeout_at(stop_token.clone()).await;
        match res {
            Ok(Some(())) => {
                // Do nothing
            }
            Ok(None) => {
                break true;
            }
            Err(_) => {
                break false;
            }
        }
    }
}
