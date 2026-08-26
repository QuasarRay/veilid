use super::*;

// Recovers a wasm-bindgen-exported veilid-core type from a `&JsValue` by reading its
// `__wbg_ptr`, used by the crypto-type macros to accept JS instances as parameters.

/// Implement `TryFrom<&JsValue>` for a wasm-bindgen type by reading its `__wbg_ptr`
/// and recovering a cloned instance from the wasm linear memory.
macro_rules! impl_try_from_js_value {
    ($name:ident) => {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        impl ::core::convert::TryFrom<&::wasm_bindgen::JsValue> for $name {
            type Error = String;

            fn try_from(js: &::wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
                use ::wasm_bindgen::convert::RefFromWasmAbi;

                let ptr =
                    ::js_sys::Reflect::get(js, &::wasm_bindgen::JsValue::from_str("__wbg_ptr"))
                        .map_err(|_| {
                            ::alloc::format!(
                                "expected {}, value is not an object",
                                ::core::stringify!($name)
                            )
                        })?;
                let ptr_u32: u32 = ptr.as_f64().ok_or_else(|| {
                    ::alloc::format!("expected {}, missing __wbg_ptr", ::core::stringify!($name))
                })? as u32;
                let wasm_ptr = ::wasm_bindgen::__rt::WasmPtr::<
                    ::wasm_bindgen::__rt::WasmRefCell<$name>,
                >::from_usize(ptr_u32 as usize);
                let instance_ref = unsafe { Self::ref_from_abi(wasm_ptr) };
                Ok(instance_ref.clone())
            }
        }
    };
}
pub(crate) use impl_try_from_js_value;

thread_local! {
    /// Builds the JS value thrown for an error: `(data, message) => any`.
    ///
    /// Unset by default, which serializes the error as a plain object. A binding crate
    /// installs one to throw its own `Error` subclasses instead; veilid-wasm does, and
    /// veilid-flutter deliberately does not, since its Dart side reads the plain form.
    static JS_ERROR_FACTORY: RefCell<Option<js_sys::Function>> = const { RefCell::new(None) };
}

/// Install the factory that builds thrown JS errors, replacing any previous one.
///
/// Call before the first fallible export runs, or errors raised until then fall back to
/// the plain serialized object.
pub fn set_js_error_factory(factory: js_sys::Function) {
    JS_ERROR_FACTORY.with_borrow_mut(|f| *f = Some(factory));
}

/// Lets `Result<_, VeilidAPIError>` cross `#[wasm_bindgen]` boundaries as a thrown
/// value, through the installed factory when there is one.
impl From<VeilidAPIError> for wasm_bindgen::JsValue {
    fn from(e: VeilidAPIError) -> Self {
        let message = wasm_bindgen::JsValue::from_str(&e.to_string());
        let data = serde_wasm_bindgen::to_value(&e).unwrap_or_else(|_| message.clone());
        JS_ERROR_FACTORY
            .with_borrow(|f| {
                f.as_ref()
                    .and_then(|factory| factory.call2(&JsValue::UNDEFINED, &data, &message).ok())
            })
            .unwrap_or(data)
    }
}
