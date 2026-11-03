#![allow(non_snake_case)]
use super::*;

static PROTOCOL_TYPE_ORDERING: LazyLock<BTreeMap<(Sequencing, ProtocolType), usize>> =
    LazyLock::new(|| {
        let mut out = BTreeMap::<(Sequencing, ProtocolType), usize>::new();

        // Sequencing::PreferUnordered
        {
            let pref = Sequencing::PreferUnordered;

            let mut order = 0;
            out.insert((pref, ProtocolType::UDP), order);

            order += 1;
            out.insert((pref, ProtocolType::TCP), order);

            order += 1;
            out.insert((pref, ProtocolType::WS), order);

            cfg_if::cfg_if! {
                if #[cfg(feature="enable-protocol-wss")] {
                    order += 1;
                    out.insert((pref, ProtocolType::WSS), order);
                }
            }
            cfg_if::cfg_if! {
                if #[cfg(feature="enable-protocol-webtransport")] {
                    order += 1;
                    out.insert((pref, ProtocolType::WTS), order);
                    order += 1;
                    out.insert((pref, ProtocolType::WTD), order);
                }
            }
        }
        // Sequencing::PreferOrdered | Sequencing::EnsureOrdered
        for pref in [Sequencing::PreferOrdered, Sequencing::EnsureOrdered] {
            let mut order = 0;
            out.insert((pref, ProtocolType::TCP), order);

            order += 1;
            out.insert((pref, ProtocolType::WS), order);

            cfg_if::cfg_if! {
                if #[cfg(feature="enable-protocol-wss")] {
                    order += 1;
                    out.insert((pref, ProtocolType::WSS), order);
                }
            }

            order += 1;
            out.insert((pref, ProtocolType::UDP), order);

            cfg_if::cfg_if! {
                if #[cfg(feature="enable-protocol-webtransport")] {
                    order += 1;
                    out.insert((pref, ProtocolType::WTS), order);
                    order += 1;
                    out.insert((pref, ProtocolType::WTD), order);
                }
            }
        }

        out
    });

static PROTOCOL_TYPE_ALL_CONNECTION_SET: LazyLock<ProtocolTypeSet> = LazyLock::new(|| {
    let mut out = ProtocolTypeSet::new();

    for pt in ProtocolTypeSet::all() {
        if pt.framing_type() == FramingType::Connection {
            out.insert(pt);
        }
    }

    out
});

pub type ProtocolTypeSort<'a> =
    dyn Fn(&ProtocolType, &ProtocolType) -> core::cmp::Ordering + Send + Sync + 'a;

// Keep member order appropriate for sorting < preference
// Must match DialInfo order
// Eventually this needs to become a FOURCC when protocols become pluggable
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Debug, PartialOrd, Ord, Hash, EnumSetType, Serialize, Deserialize)]
#[enumset(repr = "u8")]
pub(crate) enum ProtocolType {
    UDP = 0,
    TCP = 1,
    WS = 2,
    #[cfg(feature = "enable-protocol-wss")]
    WSS = 3,
    #[cfg(feature = "enable-protocol-webtransport")]
    WTS = 4,
    #[cfg(feature = "enable-protocol-webtransport")]
    WTD = 5,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct ProtocolDescriptor {
    pub framing: FramingType,
    pub ordering: SequenceOrdering,
    pub low_level: LowLevelProtocolType,
}

impl ProtocolType {
    pub(crate) fn descriptor(&self) -> ProtocolDescriptor {
        use FramingType::{Connection, Message};
        use SequenceOrdering::{Ordered, Unordered};
        match self {
            ProtocolType::UDP => ProtocolDescriptor {
                framing: Message,
                ordering: Unordered,
                low_level: LowLevelProtocolType::UDP,
            },
            ProtocolType::TCP => ProtocolDescriptor {
                framing: Connection,
                ordering: Ordered,
                low_level: LowLevelProtocolType::TCP,
            },
            ProtocolType::WS => ProtocolDescriptor {
                framing: Connection,
                ordering: Ordered,
                low_level: LowLevelProtocolType::TCP,
            },
            #[cfg(feature = "enable-protocol-wss")]
            ProtocolType::WSS => ProtocolDescriptor {
                framing: Connection,
                ordering: Ordered,
                low_level: LowLevelProtocolType::TCP,
            },
            #[cfg(feature = "enable-protocol-webtransport")]
            ProtocolType::WTS => ProtocolDescriptor {
                framing: Connection,
                ordering: Ordered,
                low_level: LowLevelProtocolType::UDP,
            },
            #[cfg(feature = "enable-protocol-webtransport")]
            ProtocolType::WTD => ProtocolDescriptor {
                framing: Message,
                ordering: Unordered,
                low_level: LowLevelProtocolType::UDP,
            },
        }
    }

    pub fn sequence_ordering(&self) -> SequenceOrdering {
        self.descriptor().ordering
    }

    pub fn framing_type(&self) -> FramingType {
        self.descriptor().framing
    }

    pub fn low_level_protocol_type(&self) -> LowLevelProtocolType {
        self.descriptor().low_level
    }
    pub fn sort_order(&self, sequencing: Sequencing) -> usize {
        *PROTOCOL_TYPE_ORDERING
            .get(&(sequencing, *self))
            .unwrap_or_log()
    }
    pub fn all_connection_set() -> ProtocolTypeSet {
        *PROTOCOL_TYPE_ALL_CONNECTION_SET
    }

    /// All protocol types matching a specific sequence ordering
    pub fn all_sequence_ordering_set(ordering: SequenceOrdering) -> ProtocolTypeSet {
        let mut out = ProtocolTypeSet::empty();
        for pt in ProtocolTypeSet::all() {
            if pt.sequence_ordering() == ordering {
                out.insert(pt);
            }
        }
        out
    }

    pub fn get_ordering_sort(ordering: SequenceOrdering) -> Option<Box<ProtocolTypeSort<'static>>> {
        match ordering {
            SequenceOrdering::Unordered => None,
            SequenceOrdering::Ordered => Some(Box::new(Self::ordered_sequencing_sort)),
        }
    }
    pub fn ordered_sequencing_sort(a: &Self, b: &Self) -> core::cmp::Ordering {
        let ca = a.sort_order(Sequencing::EnsureOrdered);
        let cb = b.sort_order(Sequencing::EnsureOrdered);
        ca.cmp(&cb)
    }

    pub fn set_from_str(s: &str) -> VeilidAPIResult<ProtocolTypeSet> {
        let s = s.to_ascii_lowercase();
        if s == "all-protocol-type" {
            return Ok(ProtocolTypeSet::all());
        }
        if s == "no-protocol-type" || s.is_empty() {
            return Ok(ProtocolTypeSet::empty());
        }
        let mut pset = ProtocolTypeSet::empty();
        for pstr in s.split("|") {
            let p = ProtocolType::from_str(pstr)?;
            pset |= p;
        }
        Ok(pset)
    }
}
impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolType::UDP => write!(f, "UDP"),
            ProtocolType::TCP => write!(f, "TCP"),
            ProtocolType::WS => write!(f, "WS"),
            #[cfg(feature = "enable-protocol-wss")]
            ProtocolType::WSS => write!(f, "WSS"),
            #[cfg(feature = "enable-protocol-webtransport")]
            ProtocolType::WTS => write!(f, "WTS"),
            #[cfg(feature = "enable-protocol-webtransport")]
            ProtocolType::WTD => write!(f, "WTD"),
        }
    }
}

impl FromStr for ProtocolType {
    type Err = VeilidAPIError;
    fn from_str(s: &str) -> VeilidAPIResult<ProtocolType> {
        match s.to_ascii_uppercase().as_str() {
            "UDP" => Ok(ProtocolType::UDP),
            "TCP" => Ok(ProtocolType::TCP),
            "WS" => Ok(ProtocolType::WS),
            #[cfg(feature = "enable-protocol-wss")]
            "WSS" => Ok(ProtocolType::WSS),
            #[cfg(feature = "enable-protocol-webtransport")]
            "WTS" => Ok(ProtocolType::WTS),
            #[cfg(feature = "enable-protocol-webtransport")]
            "WTD" => Ok(ProtocolType::WTD),
            _ => Err(VeilidAPIError::parse_error(
                "ProtocolType::from_str failed",
                s,
            )),
        }
    }
}

pub type ProtocolTypeSet = EnumSet<ProtocolType>;

#[cfg(feature = "enable-protocol-webtransport")]
pub(crate) const WEBTRANSPORT_PROTOCOL_TYPES: ProtocolTypeSet =
    enum_set!(ProtocolType::WTS | ProtocolType::WTD);
