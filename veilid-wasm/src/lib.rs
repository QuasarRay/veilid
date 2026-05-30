#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#![no_std]
#![recursion_limit = "256"]

/// Veilid WASM Bindings (TypeScript / JavaScript)
extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::*;
use core::cell::RefCell;
use core::fmt::Debug;
use core::sync::atomic::{AtomicBool, Ordering};
use js_sys::*;
use lazy_static::*;
use send_wrapper::*;
use serde::*;
use tracing_subscriber::prelude::*;
use tracing_subscriber::*;
use tsify::*;
use veilid_core::*;
use veilid_core::{tools::*, VeilidAPIError};
use veilid_tracing_wasm::*;

pub mod veilid_api_js;
pub mod veilid_client_js;
pub mod veilid_crypto_js;
pub mod veilid_routing_context_js;
pub mod veilid_table_db_js;
pub mod veilid_version;
pub mod veilid_wasm_config;

pub use veilid_api_js::*;
pub use veilid_version::*;
pub use veilid_wasm_config::*;
