use super::*;

#[wasm_bindgen(typescript_custom_section)]
const OPAQUE_NEW_TYPES: &'static str = r#"
declare const OpaqueNewTypeSymbol: unique symbol
declare class OpaqueNewType<S extends symbol> {
    private [OpaqueNewTypeSymbol]: S
}
type Opaque<T, S extends symbol> = (T & OpaqueNewType<S>) | OpaqueNewType<S>
"#;

#[macro_export]
macro_rules! impl_opaque_newtype {
    ($name:ident, $base:ident) => {
        pastey::paste! {
            #[wasm_bindgen(typescript_custom_section)]
            const [< IMPL_OPAQUE_NEW_TYPE_ $name:upper >]: &'static str = concat!(r#"
declare const "#, stringify!($name), r#"Symbol: unique symbol
export type "#, stringify!($name), r#" = Opaque<"#, stringify!($base), r#", typeof "#, stringify!($name), r#"Symbol>
"#);
        }
    };
}

#[macro_export]
macro_rules! make_wasm_bindgen_stubs {
    ($name:ident) => {
        pastey::paste! {
            #[wasm_bindgen]
            extern "C" {
                #[wasm_bindgen(typescript_type = $name)]
                pub type [< TypeStub $name >];
            }
        }
    };
}

#[macro_export]
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

/// Converts the given optional typed value into a JS value.
/// If the typed value is `None`, the result is JS `undefined`.
pub fn into_js_option<T, U>(val: Option<U>) -> T
where
    JsValue: From<U>,
    T: JsCast,
{
    let js_val = match val {
        None => JsValue::UNDEFINED,
        Some(val) => val.into(),
    };
    js_val.unchecked_into::<T>()
}

/// Attempts to unpack a JS value into a typed value,
/// returning `None` if the JS value is `undefined`.
pub fn try_from_js_option<T>(val: impl Into<JsValue>) -> Result<Option<T>, String>
where
    for<'a> T: TryFrom<&'a JsValue>,
    for<'a> <T as TryFrom<&'a JsValue>>::Error: core::fmt::Display,
{
    let js_val = val.into();
    if js_val.is_undefined() {
        return Ok(None);
    }
    T::try_from(&js_val)
        .map(Some)
        .map_err(|err| alloc::format!("{}", err))
}

/// Converts the given iterator into a JS array of the custom type `T`.
pub fn into_js_array<T, U>(value: impl IntoIterator<Item = U>) -> T
where
    JsValue: From<U>,
    T: JsCast,
{
    value
        .into_iter()
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<T>()
}

/// Attempts to unpack a JS array into a vector of typed values.
pub fn try_from_js_array<T>(val: impl Into<JsValue>) -> Result<Vec<T>, String>
where
    for<'a> T: TryFrom<&'a JsValue>,
    for<'a> <T as TryFrom<&'a JsValue>>::Error: core::fmt::Display,
{
    let js_val = val.into();
    let array: &js_sys::Array = js_val.dyn_ref().ok_or("The argument must be an array")?;
    let length: usize = array
        .length()
        .try_into()
        .map_err(|err| alloc::format!("{}", err))?;
    let mut typed_array = Vec::<T>::with_capacity(length);
    for (idx, js) in array.iter().enumerate() {
        let typed_elem = T::try_from(&js)
            .map_err(|err| alloc::format!("Failed to cast item {}: {}", idx, err))?;
        typed_array.push(typed_elem);
    }
    Ok(typed_array)
}

pub mod ts {
    use super::*;

    /// Options that override defaults for set_dht_value
    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    #[serde(rename_all = "camelCase")]
    pub struct SetDHTValueOptions {
        /// Override writer key pair for this operation
        #[tsify(type = "KeyPair", optional)]
        #[serde(with = "serde_wasm_bindgen::preserve")]
        pub writer: JsValue,
        /// Defaults to true. If false, the value will not be written if the node is offline,
        /// and a TryAgain error will be returned.
        #[tsify(optional)]
        pub allow_offline: Option<AllowOffline>,
    }

    /// Options that override defaults for transact_dht_records
    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    #[serde(rename_all = "camelCase")]
    pub struct TransactDHTRecordsOptions {
        #[tsify(type = "KeyPair", optional)]
        #[serde(with = "serde_wasm_bindgen::preserve")]
        pub default_signing_keypair: JsValue,
    }

    /// Options that override defaults for DHTTransaction::set
    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    pub struct DHTTransactionSetValueOptions {
        /// Override writer key pair for this operation
        #[tsify(type = "KeyPair", optional)]
        #[serde(with = "serde_wasm_bindgen::preserve")]
        pub writer: JsValue,
    }

    /// Simple DHT Schema (SMPL) Member
    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    #[serde(rename_all = "camelCase")]
    pub struct DHTSchemaSMPLMember {
        /// Member key
        #[tsify(type = "BareMemberId")]
        #[serde(with = "serde_wasm_bindgen::preserve")]
        pub m_key: JsValue,
        /// Member subkey count
        pub m_cnt: u16,
    }

    /// Simple DHT Schema (SMPL)
    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    #[serde(rename_all = "camelCase")]
    pub struct DHTSchemaSMPL {
        /// Owner subkey count
        pub o_cnt: u16,
        /// Members
        pub members: Vec<DHTSchemaSMPLMember>,
    }

    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi, namespace)]
    pub enum DHTSchema {
        DFLT(DHTSchemaDFLT),
        SMPL(DHTSchemaSMPL),
    }

    /// DHT Record Descriptor
    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    #[serde(rename_all = "camelCase")]
    pub struct DHTRecordDescriptor {
        /// DHT Key = Hash(ownerKeyKind) of: [ ownerKeyValue, schema ]
        #[tsify(type = "RecordKey")]
        #[serde(with = "serde_wasm_bindgen::preserve")]
        pub key: JsValue,
        /// The public key of the owner
        /// If this key is being created: KeyPair
        /// If this key is just being opened: PublicKey
        #[tsify(type = "PublicKey | KeyPair")]
        #[serde(with = "serde_wasm_bindgen::preserve")]
        pub owner: JsValue,
        /// The schema in use associated with the key
        pub schema: DHTSchema,
    }

    /// A DHT value and its metadata
    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    #[serde(rename_all = "camelCase")]
    pub struct ValueData {
        /// An increasing sequence number to time-order the DHT record changes
        pub seq: ValueSeqNum,

        /// The contents of a DHT Record
        #[cfg_attr(
            all(target_arch = "wasm32", target_os = "unknown"),
            serde(with = "serde_bytes"),
            tsify(type = "Uint8Array")
        )]
        pub data: Vec<u8>,

        /// The public identity key of the writer of the data
        #[tsify(type = "PublicKey")]
        #[serde(with = "serde_wasm_bindgen::preserve")]
        pub writer: JsValue,
    }

    /// Safety spec
    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    #[serde(rename_all = "camelCase")]
    pub struct SafetySpec {
        #[tsify(optional)]
        #[serde(default)]
        pub hop_count: usize,
        #[tsify(optional)]
        #[serde(default)]
        pub stability: Stability,
        #[tsify(optional)]
        #[serde(default)]
        pub sequencing: Sequencing,
        #[tsify(type = "RouteId", optional)]
        #[serde(default, with = "serde_wasm_bindgen::preserve")]
        pub preferred_route: JsValue,
    }

    /// Private spec
    #[derive(Serialize, Deserialize, Clone, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    #[serde(rename_all = "camelCase")]
    pub struct PrivateSpec {
        #[tsify(optional)]
        #[serde(default)]
        pub crypto_kinds: Vec<CryptoKind>,
        #[tsify(optional)]
        #[serde(default)]
        pub hop_count: usize,
        #[tsify(optional)]
        #[serde(default)]
        pub stability: Stability,
        #[tsify(optional)]
        #[serde(default)]
        pub sequencing: Sequencing,
    }

    /// Route blob
    #[derive(Clone, Deserialize, Serialize, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi)]
    #[serde(rename_all = "camelCase")]
    pub struct RouteBlob {
        #[tsify(type = "RouteId")]
        #[serde(with = "serde_wasm_bindgen::preserve")]
        pub route_id: JsValue,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        pub blob: Vec<u8>,
    }

    /// The choice of safety route to include in compiled routes.
    #[derive(Clone, Serialize, Deserialize, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi, namespace)]
    pub enum SafetySelection {
        /// Don't use a safety route, only specify the sequencing preference.
        Unsafe(Sequencing),
        /// Use a safety route and parameters specified by a SafetySpec.
        Safe(ts::SafetySpec),
    }

    /// The choice of safety route to include in compiled routes.
    #[derive(Clone, Serialize, Deserialize, Tsify)]
    #[tsify(from_wasm_abi, into_wasm_abi, namespace)]
    pub enum Target {
        /// Node by its node id
        NodeId(
            #[tsify(type = "NodeId")]
            #[serde(with = "serde_wasm_bindgen::preserve")]
            JsValue,
        ),
        /// Remote private route by its id.
        RouteId(
            #[tsify(type = "RouteId")]
            #[serde(with = "serde_wasm_bindgen::preserve")]
            JsValue,
        ),
    }
}

impl TryFrom<ts::SetDHTValueOptions> for SetDHTValueOptions {
    type Error = VeilidAPIError;

    fn try_from(value: ts::SetDHTValueOptions) -> Result<Self, Self::Error> {
        let writer =
            try_from_js_option::<KeyPair>(value.writer).map_err(VeilidAPIError::generic)?;
        let allow_offline = value.allow_offline.clone();
        Ok(SetDHTValueOptions {
            writer,
            allow_offline,
        })
    }
}

impl TryFrom<ts::TransactDHTRecordsOptions> for TransactDHTRecordsOptions {
    type Error = VeilidAPIError;

    fn try_from(value: ts::TransactDHTRecordsOptions) -> Result<Self, Self::Error> {
        let default_signing_keypair = try_from_js_option::<KeyPair>(value.default_signing_keypair)
            .map_err(VeilidAPIError::generic)?;
        Ok(TransactDHTRecordsOptions {
            default_signing_keypair,
        })
    }
}

impl TryFrom<ts::DHTTransactionSetValueOptions> for DHTTransactionSetValueOptions {
    type Error = VeilidAPIError;

    fn try_from(value: ts::DHTTransactionSetValueOptions) -> Result<Self, Self::Error> {
        let writer =
            try_from_js_option::<KeyPair>(value.writer).map_err(VeilidAPIError::generic)?;
        Ok(DHTTransactionSetValueOptions { writer })
    }
}

impl TryFrom<ts::DHTSchemaSMPLMember> for DHTSchemaSMPLMember {
    type Error = VeilidAPIError;

    fn try_from(value: ts::DHTSchemaSMPLMember) -> Result<Self, Self::Error> {
        let Some(m_key) = try_from_js_option::<BareMemberId>(value.m_key.clone())
            .map_err(VeilidAPIError::generic)?
        else {
            apibail_missing_argument!("m_key must not be undefined", "m_key");
        };
        let m_cnt = value.m_cnt;
        Ok(DHTSchemaSMPLMember { m_key, m_cnt })
    }
}

impl From<DHTSchemaSMPLMember> for ts::DHTSchemaSMPLMember {
    fn from(value: DHTSchemaSMPLMember) -> Self {
        ts::DHTSchemaSMPLMember {
            m_key: value.m_key.into(),
            m_cnt: value.m_cnt,
        }
    }
}

impl TryFrom<ts::DHTSchemaSMPL> for DHTSchemaSMPL {
    type Error = VeilidAPIError;

    fn try_from(value: ts::DHTSchemaSMPL) -> Result<Self, Self::Error> {
        let o_cnt = value.o_cnt;
        let mut members = vec![];
        for member in value.members {
            members.push(member.try_into().map_err(VeilidAPIError::generic)?);
        }
        DHTSchemaSMPL::new(o_cnt, members)
    }
}

impl From<DHTSchemaSMPL> for ts::DHTSchemaSMPL {
    fn from(value: DHTSchemaSMPL) -> Self {
        let mut members = vec![];
        for member in value.members() {
            members.push(member.clone().into())
        }

        ts::DHTSchemaSMPL {
            o_cnt: value.o_cnt(),
            members,
        }
    }
}

impl TryFrom<ts::DHTSchema> for DHTSchema {
    type Error = VeilidAPIError;

    fn try_from(value: ts::DHTSchema) -> Result<Self, Self::Error> {
        match value {
            ts::DHTSchema::DFLT(d) => Ok(DHTSchema::DFLT(d)),
            ts::DHTSchema::SMPL(s) => Ok(DHTSchema::SMPL(s.try_into()?)),
        }
    }
}

impl From<DHTSchema> for ts::DHTSchema {
    fn from(value: DHTSchema) -> Self {
        match value {
            DHTSchema::DFLT(d) => ts::DHTSchema::DFLT(d),
            DHTSchema::SMPL(s) => ts::DHTSchema::SMPL(s.into()),
        }
    }
}

impl TryFrom<ts::DHTRecordDescriptor> for DHTRecordDescriptor {
    type Error = VeilidAPIError;

    fn try_from(value: ts::DHTRecordDescriptor) -> Result<Self, Self::Error> {
        let Some(key) =
            try_from_js_option::<RecordKey>(value.key.clone()).map_err(VeilidAPIError::generic)?
        else {
            apibail_missing_argument!("key must not be undefined", "key");
        };
        let (owner, owner_secret) = match try_from_js_option::<KeyPair>(value.owner.clone()) {
            Ok(Some(v)) => (v.key(), Some(v.secret())),
            Ok(None) => {
                apibail_missing_argument!("owner must not be undefined", "owner");
            }
            Err(_) => match try_from_js_option::<PublicKey>(value.owner.clone()) {
                Ok(Some(v)) => (v, None),
                Err(e) => apibail_generic!(e),
                Ok(None) => {
                    apibail_missing_argument!("owner must not be undefined", "owner");
                }
            },
        };

        let schema = value.schema.try_into()?;

        Ok(DHTRecordDescriptor::new(key, owner, owner_secret, schema))
    }
}

impl From<DHTRecordDescriptor> for ts::DHTRecordDescriptor {
    fn from(value: DHTRecordDescriptor) -> Self {
        ts::DHTRecordDescriptor {
            key: value.key().into(),
            owner: match value.owner_keypair() {
                Some(owner_keypair) => owner_keypair.into(),
                None => value.owner().into(),
            },
            schema: value.schema().into(),
        }
    }
}

impl From<ValueData> for ts::ValueData {
    fn from(value: ValueData) -> Self {
        ts::ValueData {
            seq: value.seq(),
            data: value.data().to_vec(),
            writer: value.writer().into(),
        }
    }
}

impl TryFrom<ts::SafetySpec> for SafetySpec {
    type Error = VeilidAPIError;

    fn try_from(value: ts::SafetySpec) -> Result<Self, Self::Error> {
        let hop_count = value.hop_count;
        let stability = value.stability;
        let sequencing = value.sequencing;
        let preferred_route = try_from_js_option::<RouteId>(value.preferred_route)
            .map_err(VeilidAPIError::generic)?;
        Ok(SafetySpec {
            hop_count,
            stability,
            sequencing,
            preferred_route,
        })
    }
}

impl From<SafetySpec> for ts::SafetySpec {
    fn from(value: SafetySpec) -> Self {
        ts::SafetySpec {
            hop_count: value.hop_count,
            stability: value.stability,
            sequencing: value.sequencing,
            preferred_route: value.preferred_route.into(),
        }
    }
}

impl TryFrom<ts::PrivateSpec> for PrivateSpec {
    type Error = VeilidAPIError;

    fn try_from(value: ts::PrivateSpec) -> Result<Self, Self::Error> {
        let crypto_kinds = value.crypto_kinds;
        let hop_count = value.hop_count;
        let stability = value.stability;
        let sequencing = value.sequencing;
        Ok(PrivateSpec {
            crypto_kinds,
            hop_count,
            stability,
            sequencing,
        })
    }
}

impl From<PrivateSpec> for ts::PrivateSpec {
    fn from(value: PrivateSpec) -> Self {
        ts::PrivateSpec {
            crypto_kinds: value.crypto_kinds,
            hop_count: value.hop_count,
            stability: value.stability,
            sequencing: value.sequencing,
        }
    }
}

impl TryFrom<ts::RouteBlob> for RouteBlob {
    type Error = VeilidAPIError;

    fn try_from(value: ts::RouteBlob) -> Result<Self, Self::Error> {
        let Some(route_id) =
            try_from_js_option::<RouteId>(value.route_id).map_err(VeilidAPIError::generic)?
        else {
            apibail_missing_argument!("route_id must not be undefined", "route_id");
        };
        let blob = value.blob;
        Ok(RouteBlob { route_id, blob })
    }
}

impl From<RouteBlob> for ts::RouteBlob {
    fn from(value: RouteBlob) -> Self {
        ts::RouteBlob {
            route_id: value.route_id.into(),
            blob: value.blob,
        }
    }
}

impl TryFrom<ts::SafetySelection> for SafetySelection {
    type Error = VeilidAPIError;

    fn try_from(value: ts::SafetySelection) -> Result<Self, Self::Error> {
        match value {
            ts::SafetySelection::Unsafe(seq) => Ok(SafetySelection::Unsafe(seq)),
            ts::SafetySelection::Safe(ss) => Ok(SafetySelection::Safe(ss.try_into()?)),
        }
    }
}

impl From<SafetySelection> for ts::SafetySelection {
    fn from(value: SafetySelection) -> Self {
        match value {
            SafetySelection::Unsafe(seq) => ts::SafetySelection::Unsafe(seq),
            SafetySelection::Safe(ss) => ts::SafetySelection::Safe(ss.into()),
        }
    }
}

impl TryFrom<ts::Target> for Target {
    type Error = VeilidAPIError;

    fn try_from(value: ts::Target) -> Result<Self, Self::Error> {
        match value {
            ts::Target::NodeId(node_id) => Ok(Target::NodeId(
                NodeId::try_from(&node_id).map_err(VeilidAPIError::generic)?,
            )),
            ts::Target::RouteId(route_id) => Ok(Target::RouteId(
                RouteId::try_from(&route_id).map_err(VeilidAPIError::generic)?,
            )),
        }
    }
}

impl From<Target> for ts::Target {
    fn from(value: Target) -> Self {
        match value {
            Target::NodeId(node_id) => ts::Target::NodeId(node_id.into()),
            Target::RouteId(route_id) => ts::Target::RouteId(route_id.into()),
        }
    }
}
