use super::*;

/// The state of a timestamp, either live (not expired) or dead (expired)
#[derive(
    Debug, Default, PartialEq, Eq, Clone, Copy, Hash, Serialize, Deserialize, JsonSchema, GetSize,
)]
#[must_use]
pub enum ExpirationState {
    #[default]
    Live,
    Dead,
}

impl fmt::Display for ExpirationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ExpirationState::Live => "live",
                ExpirationState::Dead => "dead",
            }
        )
    }
}
