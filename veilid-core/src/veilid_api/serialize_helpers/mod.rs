use super::*;
use core::fmt::Debug;

mod compression;
mod get_size_helpers;
/// serde `with`-module that (de)serializes an `Arc<T>` transparently as its inner `T`.
pub mod serialize_arc;
mod serialize_json;
/// serde `with`-module that (de)serializes a `RangeSetBlaze<T>` as a sequence of inclusive `(start, end)` pairs.
pub mod serialize_range_set_blaze;
mod serialize_untyped_vld0;

pub(crate) use compression::*;
pub(crate) use get_size_helpers::*;
pub use serialize_json::*;
pub use serialize_untyped_vld0::*;
