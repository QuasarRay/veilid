#![allow(non_snake_case)]

use super::*;

// XXX: Eventually this needs to become a FOURCC when low level protocols become pluggable
// Keep member order appropriate for sorting < preference
// Must match DialInfo order
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) enum LowLevelProtocolType {
    UDP = 0,
    TCP = 1,
}

impl fmt::Display for LowLevelProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LowLevelProtocolType::UDP => "UDP",
                LowLevelProtocolType::TCP => "TCP",
            }
        )
    }
}

impl LowLevelProtocolType {
    pub fn is_connection_oriented(&self) -> bool {
        matches!(self, Self::TCP)
    }
}
