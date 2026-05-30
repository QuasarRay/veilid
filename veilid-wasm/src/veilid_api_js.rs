use super::*;

// API Singleton
lazy_static! {
    pub static ref VEILID_API: SendWrapper<RefCell<Option<VeilidAPI>>> =
        SendWrapper::new(RefCell::new(None));
    pub static ref FILTERS: SendWrapper<RefCell<BTreeMap<&'static str, VeilidLayerFilter>>> =
        SendWrapper::new(RefCell::new(BTreeMap::new()));
}

pub fn get_veilid_api() -> Result<VeilidAPI, veilid_core::VeilidAPIError> {
    (*VEILID_API)
        .borrow()
        .clone()
        .ok_or(VeilidAPIError::NotInitialized)
}

pub fn take_veilid_api() -> Result<VeilidAPI, VeilidAPIError> {
    (**VEILID_API).take().ok_or(VeilidAPIError::NotInitialized)
}
