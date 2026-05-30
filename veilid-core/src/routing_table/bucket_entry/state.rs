use super::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum BucketEntryStateReason {
    Punished(PunishmentReason),
    Dead(BucketEntryTransportDeadReason),
    Unreliable(BucketEntryTransportUnreliableReason),
    Reliable,
}

impl fmt::Display for BucketEntryStateReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            match self {
                BucketEntryStateReason::Punished(p) => write!(f, "{}", f.to_string(p)),
                BucketEntryStateReason::Dead(d) => write!(f, "{}", f.to_string(d)),
                BucketEntryStateReason::Unreliable(u) => write!(f, "{}", f.to_string(u)),
                BucketEntryStateReason::Reliable => write!(f, "RELIBL"),
            }
        } else {
            match self {
                BucketEntryStateReason::Punished(p) => write!(f, "Punished({})", f.to_string(p)),
                BucketEntryStateReason::Dead(d) => write!(f, "Dead({})", f.to_string(d)),
                BucketEntryStateReason::Unreliable(u) => {
                    write!(f, "Unreliable({})", f.to_string(u))
                }
                BucketEntryStateReason::Reliable => write!(f, "Reliable"),
            }
        }
    }
}

// Do not change order here, it will mess up other sorts
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BucketEntryState {
    Punished,
    Dead,
    Unreliable,
    Reliable,
}

impl BucketEntryState {
    pub fn is_alive(&self) -> bool {
        match self {
            BucketEntryState::Punished => false,
            BucketEntryState::Dead => false,
            BucketEntryState::Unreliable => true,
            BucketEntryState::Reliable => true,
        }
    }
    pub fn ordering(&self) -> usize {
        match self {
            BucketEntryState::Punished => 0,
            BucketEntryState::Dead => 1,
            BucketEntryState::Unreliable => 2,
            BucketEntryState::Reliable => 3,
        }
    }
}

impl From<BucketEntryStateReason> for BucketEntryState {
    fn from(value: BucketEntryStateReason) -> Self {
        match value {
            BucketEntryStateReason::Punished(_) => BucketEntryState::Punished,
            BucketEntryStateReason::Dead(_) => BucketEntryState::Dead,
            BucketEntryStateReason::Unreliable(_) => BucketEntryState::Unreliable,
            BucketEntryStateReason::Reliable => BucketEntryState::Reliable,
        }
    }
}
