mod bootstrap_record;
mod debug;
mod dial_info_converter;
mod direct_bootstrap;
mod txt_bootstrap;

use super::*;

/// Port a bootstrap host answers B01T on when a TXT name has to be reached directly
pub const BOOTSTRAP_DIRECT_PORT: u16 = 5150;

pub use bootstrap_record::*;
pub use dial_info_converter::*;
pub use txt_bootstrap::*;

/// Result of one bootstrap resolution: peers to bootstrap with, and the records they came from
#[derive(Debug, Default)]
pub struct BootstrapPeers {
    pub peers: Vec<Arc<PeerInfo>>,
    pub records: Vec<BootstrapRecord>,
}
