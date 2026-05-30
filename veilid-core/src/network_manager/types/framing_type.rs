use super::*;

/// High-level protocol framing: a continuous byte stream (Connection) or
/// discrete messages (Message). Orthogonal to the underlying socket type
/// (e.g. WebTransport-stream is Connection framing over a Datagram socket).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) enum FramingType {
    Connection,
    Message,
}

impl fmt::Display for FramingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            match self {
                FramingType::Connection => write!(f, "CONN"),
                FramingType::Message => write!(f, "MESG"),
            }
        } else {
            match self {
                FramingType::Connection => write!(f, "Connection"),
                FramingType::Message => write!(f, "Message"),
            }
        }
    }
}
