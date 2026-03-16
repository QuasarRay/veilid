use super::*;

impl_veilid_log_facility!("rtab");

/// Minimum number of nodes after initial discovery for a routing domain
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingDomainLowWaterMark {
    lwm_per_crypto_kind: BTreeMap<CryptoKind, usize>,
}

impl RoutingDomainLowWaterMark {
    pub fn new() -> Self {
        Self {
            lwm_per_crypto_kind: BTreeMap::new(),
        }
    }

    pub fn set(&mut self, crypto_kind: CryptoKind, count: usize) {
        self.lwm_per_crypto_kind.insert(crypto_kind, count);
    }

    pub fn get(&self, crypto_kind: CryptoKind) -> Option<usize> {
        self.lwm_per_crypto_kind.get(&crypto_kind).copied()
    }

    pub fn min_assign(&mut self, other: &RoutingDomainLowWaterMark) {
        for (crypto_kind, count) in other.lwm_per_crypto_kind.iter() {
            self.lwm_per_crypto_kind
                .entry(*crypto_kind)
                .and_modify(|x| x.min_assign(*count))
                .or_insert(*count);
        }
    }
}

impl fmt::Display for RoutingDomainLowWaterMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lwm_per_crypto_kind.is_empty() {
            write!(f, "[empty]")
        } else {
            write!(
                f,
                "[{}]",
                self.lwm_per_crypto_kind
                    .iter()
                    .map(|(ck, count)| format!("{}={}", ck, count))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}
