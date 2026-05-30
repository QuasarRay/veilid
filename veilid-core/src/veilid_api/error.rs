use super::*;

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_not_initialized {
    () => {
        return Err(VeilidAPIError::not_initialized())
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_timeout {
    () => {
        return Err(VeilidAPIError::timeout())
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_try_again {
    ($x:expr) => {
        return Err(VeilidAPIError::try_again($x))
    };
    ($fmt:literal, $($args:tt)*) => {
        return Err(VeilidAPIError::try_again( format!($fmt, $($args)*) ))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_generic {
    ($x:expr) => {
        return Err(VeilidAPIError::generic($x))
    };
    ($fmt:literal, $($args:tt)*) => {
        return Err(VeilidAPIError::generic( format!($fmt, $($args)*) ))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_internal {
    ($x:expr) => {
        return Err(VeilidAPIError::internal($x))
    };
    ($fmt:literal, $($args:tt)*) => {
        return Err(VeilidAPIError::internal( format!($fmt, $($args)*) ))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_parse_error {
    ($x:expr, $y:expr) => {
        return Err(VeilidAPIError::parse_error($x, $y))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_missing_argument {
    ($x:expr, $y:expr) => {
        return Err(VeilidAPIError::missing_argument($x, $y))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_invalid_argument {
    ($x:expr, $y:expr, $z:expr) => {
        return Err(VeilidAPIError::invalid_argument($x, $y, $z))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_no_connection {
    ($x:expr) => {
        return Err(VeilidAPIError::no_connection($x))
    };
    ($fmt:literal, $($args: tt)* ) => {
        return Err(VeilidAPIError::no_connection( format!($fmt, arg $($args)*) ))
    };

}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_key_not_found {
    ($x:expr) => {
        return Err(VeilidAPIError::key_not_found($x))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_invalid_target {
    ($x:expr) => {
        return Err(VeilidAPIError::invalid_target($x))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_route_not_found {
    ($x:expr) => {
        return Err(VeilidAPIError::route_not_found($x))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_transaction_not_found {
    ($x:expr) => {
        return Err(VeilidAPIError::transaction_not_found($x))
    };
    ($fmt:literal, $($args:tt)*) => {
        return Err(VeilidAPIError::transaction_not_found( format!($fmt, $($args)*) ))
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! apibail_already_initialized {
    () => {
        return Err(VeilidAPIError::already_initialized())
    };
}

#[derive(
    ThisError, Clone, Debug, PartialOrd, PartialEq, Eq, Ord, Serialize, Deserialize, JsonSchema,
)]
#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    derive(Tsify),
    tsify(into_wasm_abi)
)]
#[serde(tag = "kind")]
#[must_use]
pub enum VeilidAPIError {
    #[error("Not initialized")]
    NotInitialized,
    #[error("Already initialized")]
    AlreadyInitialized,
    #[error("Timeout")]
    Timeout,
    #[error("TryAgain: {message}")]
    TryAgain { message: String },
    #[error("Invalid target: {message}")]
    InvalidTarget { message: String },
    #[error("No connection: {message}")]
    NoConnection { message: String },
    #[error("Shutdown")]
    Shutdown,
    #[error("Key not found: {key}")]
    KeyNotFound {
        #[schemars(with = "String")]
        key: OpaqueRecordKey,
    },
    #[error("Internal: {message}")]
    Internal { message: String },
    #[error("Unimplemented: {message}")]
    Unimplemented { message: String },
    #[error("Parse error: '{message}' with value '{value}'")]
    ParseError { message: String, value: String },
    #[error("Invalid argument: '{context}' for '{argument}' with value '{value}'")]
    InvalidArgument {
        context: String,
        argument: String,
        value: String,
    },
    #[error("Missing argument: '{context}' for '{argument}'")]
    MissingArgument { context: String, argument: String },
    #[error("Generic: {message}")]
    Generic { message: String },
    #[error("Transaction not found: {message}")]
    TransactionNotFound { message: String },
}

impl VeilidAPIError {
    pub fn not_initialized() -> Self {
        Self::NotInitialized
    }
    pub fn already_initialized() -> Self {
        Self::AlreadyInitialized
    }
    pub fn timeout() -> Self {
        Self::Timeout
    }
    pub fn try_again<T: ToVeilidAPIErrorArgument>(msg: T) -> Self {
        Self::TryAgain {
            message: msg.to_veilid_api_error_argument(),
        }
    }
    pub fn shutdown() -> Self {
        Self::Shutdown
    }
    pub fn invalid_target<T: ToVeilidAPIErrorArgument>(msg: T) -> Self {
        Self::InvalidTarget {
            message: msg.to_veilid_api_error_argument(),
        }
    }
    pub fn no_connection<T: ToVeilidAPIErrorArgument>(msg: T) -> Self {
        Self::NoConnection {
            message: msg.to_veilid_api_error_argument(),
        }
    }
    pub fn key_not_found(key: OpaqueRecordKey) -> Self {
        Self::KeyNotFound { key }
    }
    pub fn parse_error<T: ToVeilidAPIErrorArgument, S: ToVeilidAPIErrorArgument>(
        msg: T,
        value: S,
    ) -> Self {
        Self::ParseError {
            message: msg.to_veilid_api_error_argument(),
            value: value.to_veilid_api_error_argument(),
        }
    }
    pub fn invalid_argument<
        T: ToVeilidAPIErrorArgument,
        S: ToVeilidAPIErrorArgument,
        R: ToVeilidAPIErrorArgument,
    >(
        context: T,
        argument: S,
        value: R,
    ) -> Self {
        Self::InvalidArgument {
            context: context.to_veilid_api_error_argument(),
            argument: argument.to_veilid_api_error_argument(),
            value: value.to_veilid_api_error_argument(),
        }
    }
    pub fn missing_argument<T: ToVeilidAPIErrorArgument, S: ToVeilidAPIErrorArgument>(
        context: T,
        argument: S,
    ) -> Self {
        Self::MissingArgument {
            context: context.to_veilid_api_error_argument(),
            argument: argument.to_veilid_api_error_argument(),
        }
    }
    pub fn generic<T: ToVeilidAPIErrorArgument>(msg: T) -> Self {
        Self::Generic {
            message: msg.to_veilid_api_error_argument(),
        }
    }
    pub(crate) fn transaction_not_found<T: ToVeilidAPIErrorArgument>(msg: T) -> Self {
        Self::TransactionNotFound {
            message: msg.to_veilid_api_error_argument(),
        }
    }

    pub fn from_network_result<T>(nr: NetworkResult<T>) -> Result<T, Self> {
        match nr {
            NetworkResult::Timeout => Err(VeilidAPIError::timeout()),
            NetworkResult::ServiceUnavailable(m) => Err(VeilidAPIError::invalid_target(m)),
            NetworkResult::NoConnection(m) => Err(VeilidAPIError::no_connection(m.to_string())),
            NetworkResult::AlreadyExists(m) => Err(VeilidAPIError::no_connection(format!(
                "Already exists: {}",
                m
            ))),
            NetworkResult::InvalidMessage(m) => {
                Err(VeilidAPIError::parse_error("Invalid message", m))
            }
            NetworkResult::Value(v) => Ok(v),
        }
    }

    pub fn log_level(&self) -> Level {
        match self {
            VeilidAPIError::NotInitialized
            | VeilidAPIError::AlreadyInitialized
            | VeilidAPIError::InvalidTarget { message: _ }
            | VeilidAPIError::Internal { message: _ }
            | VeilidAPIError::Generic { message: _ }
            | VeilidAPIError::ParseError {
                message: _,
                value: _,
            }
            | VeilidAPIError::InvalidArgument {
                context: _,
                argument: _,
                value: _,
            }
            | VeilidAPIError::MissingArgument {
                context: _,
                argument: _,
            }
            | VeilidAPIError::Shutdown => Level::ERROR,

            VeilidAPIError::NoConnection { message: _ }
            | VeilidAPIError::KeyNotFound { key: _ }
            | VeilidAPIError::Unimplemented { message: _ } => Level::WARN,

            VeilidAPIError::Timeout
            | VeilidAPIError::TryAgain { message: _ }
            | VeilidAPIError::TransactionNotFound { message: _ } => Level::DEBUG,
        }
    }

    pub fn internal<T: ToString>(msg: T) -> Self {
        let message = msg.to_string();
        // Constructing an internal error should get logged because it must be a programming error on our part
        // veilid_log!(acc error "Internal error: {}", &message);
        Self::Internal { message }
    }
    pub fn unimplemented<T: ToString>(msg: T) -> Self {
        let message = msg.to_string();
        // Constructing an unimplemented error should get logged because it must be a programming error on our part
        // veilid_log!(acc error "Unimplemented: {}", &message);
        Self::Unimplemented { message }
    }
}

/////////////////////////////////////////////////////////////////////////////////////////

/// Trait for types that can be directly converted into parameters for VeilidAPIError
pub trait ToVeilidAPIErrorArgument {
    fn to_veilid_api_error_argument(&self) -> String;
}

impl ToVeilidAPIErrorArgument for String {
    fn to_veilid_api_error_argument(&self) -> String {
        self.clone()
    }
}
impl ToVeilidAPIErrorArgument for str {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for [u8] {
    fn to_veilid_api_error_argument(&self) -> String {
        hex::encode(self)
    }
}
impl ToVeilidAPIErrorArgument for Vec<u8> {
    fn to_veilid_api_error_argument(&self) -> String {
        hex::encode(self)
    }
}

impl ToVeilidAPIErrorArgument for usize {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for u64 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for u32 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for u16 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for u8 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for isize {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for i64 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for i32 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for i16 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for i8 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for f64 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for f32 {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}

impl<T: ToVeilidAPIErrorArgument> ToVeilidAPIErrorArgument for core::ops::Range<T> {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}..{}",
            self.start.to_veilid_api_error_argument(),
            self.end.to_veilid_api_error_argument()
        )
    }
}

impl ToVeilidAPIErrorArgument for Timestamp {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for TimestampDuration {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for ValueSeqNum {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for ValueSubkeyRangeSet {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for CryptoKind {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for VeilidCapability {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}

impl ToVeilidAPIErrorArgument for RouteId {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for NodeId {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for PublicKey {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for SecretKey {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}:{}",
            self.kind(),
            self.ref_value().to_veilid_api_error_argument()
        )
    }
}
impl ToVeilidAPIErrorArgument for SharedSecret {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}:{}",
            self.kind(),
            self.ref_value().to_veilid_api_error_argument()
        )
    }
}
impl ToVeilidAPIErrorArgument for Signature {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}:{}",
            self.kind(),
            self.ref_value().to_veilid_api_error_argument()
        )
    }
}
impl ToVeilidAPIErrorArgument for HashDigest {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}:{}",
            self.kind(),
            self.ref_value().to_veilid_api_error_argument()
        )
    }
}
impl ToVeilidAPIErrorArgument for KeyPair {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}:{}",
            self.kind(),
            self.ref_value().to_veilid_api_error_argument(),
        )
    }
}
impl ToVeilidAPIErrorArgument for RecordKey {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}:{}",
            self.kind(),
            self.value().to_veilid_api_error_argument()
        )
    }
}
impl ToVeilidAPIErrorArgument for MemberId {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for OpaqueRecordKey {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}:{}",
            self.kind(),
            self.ref_value().to_veilid_api_error_argument()
        )
    }
}
impl ToVeilidAPIErrorArgument for BareRecordKey {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}{}",
            self.ref_key(),
            self.ref_encryption_key()
                .map(|ek| ek.to_veilid_api_error_argument())
                .unwrap_or("".to_string())
        )
    }
}
impl ToVeilidAPIErrorArgument for BareKeyPair {
    fn to_veilid_api_error_argument(&self) -> String {
        format!(
            "{}:{}",
            self.ref_key().to_veilid_api_error_argument(),
            self.ref_secret().to_veilid_api_error_argument()
        )
    }
}
impl ToVeilidAPIErrorArgument for BarePublicKey {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for BareSecretKey {
    fn to_veilid_api_error_argument(&self) -> String {
        "*".repeat(self.to_string().len())
    }
}
impl ToVeilidAPIErrorArgument for BareSharedSecret {
    fn to_veilid_api_error_argument(&self) -> String {
        "*".repeat(self.to_string().len())
    }
}
impl ToVeilidAPIErrorArgument for BareSignature {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for BareHashDigest {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for BareOpaqueRecordKey {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}
impl ToVeilidAPIErrorArgument for BareMemberId {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}

impl ToVeilidAPIErrorArgument for serde_json::Error {
    fn to_veilid_api_error_argument(&self) -> String {
        self.to_string()
    }
}

impl<T: ToVeilidAPIErrorArgument + ?Sized> ToVeilidAPIErrorArgument for &T {
    fn to_veilid_api_error_argument(&self) -> String {
        (**self).to_veilid_api_error_argument()
    }
}

/////////////////////////////////////////////////////////////////////////////////////////

/// Result type for public Veilid API errors
pub type VeilidAPIResult<T> = Result<T, VeilidAPIError>;

pub trait OkVeilidAPIResult<T> {
    fn ok_try_again(self) -> VeilidAPIResult<Option<T>>;
    fn ok_try_again_timeout(self) -> VeilidAPIResult<Option<T>>;
}

impl<T> OkVeilidAPIResult<T> for VeilidAPIResult<Option<T>> {
    fn ok_try_again(self) -> VeilidAPIResult<Option<T>> {
        match self {
            Ok(v) => Ok(v),
            Err(VeilidAPIError::TryAgain { message: _ }) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn ok_try_again_timeout(self) -> VeilidAPIResult<Option<T>> {
        match self {
            Ok(v) => Ok(v),
            Err(VeilidAPIError::TryAgain { message: _ }) => Ok(None),
            Err(VeilidAPIError::Timeout) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl From<std::io::Error> for VeilidAPIError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::TimedOut => VeilidAPIError::timeout(),
            std::io::ErrorKind::ConnectionRefused => VeilidAPIError::no_connection(e.to_string()),
            std::io::ErrorKind::ConnectionReset => VeilidAPIError::no_connection(e.to_string()),
            // #[cfg(feature = "io_error_more")]
            // std::io::ErrorKind::HostUnreachable => VeilidAPIError::no_connection(e.to_string()),
            // #[cfg(feature = "io_error_more")]
            // std::io::ErrorKind::NetworkUnreachable => VeilidAPIError::no_connection(e.to_string()),
            std::io::ErrorKind::ConnectionAborted => VeilidAPIError::no_connection(e.to_string()),
            std::io::ErrorKind::NotConnected => VeilidAPIError::no_connection(e.to_string()),
            std::io::ErrorKind::AddrInUse => VeilidAPIError::no_connection(e.to_string()),
            std::io::ErrorKind::AddrNotAvailable => VeilidAPIError::no_connection(e.to_string()),
            // #[cfg(feature = "io_error_more")]
            // std::io::ErrorKind::NetworkDown => VeilidAPIError::no_connection(e.to_string()),
            // #[cfg(feature = "io_error_more")]
            // std::io::ErrorKind::ReadOnlyFilesystem => VeilidAPIError::internal(e.to_string()),
            // #[cfg(feature = "io_error_more")]
            // std::io::ErrorKind::NotSeekable => VeilidAPIError::internal(e.to_string()),
            // #[cfg(feature = "io_error_more")]
            // std::io::ErrorKind::FilesystemQuotaExceeded => VeilidAPIError::internal(e.to_string()),
            // #[cfg(feature = "io_error_more")]
            // std::io::ErrorKind::Deadlock => VeilidAPIError::internal(e.to_string()),
            std::io::ErrorKind::Unsupported => VeilidAPIError::internal(e.to_string()),
            std::io::ErrorKind::OutOfMemory => VeilidAPIError::internal(e.to_string()),
            _ => VeilidAPIError::generic(e.to_string()),
        }
    }
}
