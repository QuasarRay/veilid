//! Minimal DNS client for the two lookups veilid performs at bootstrap: TXT and PTR.
//!
//! A lookup asks the nameservers of one list according to a [`ResolutionStrategy`]. DNS runs
//! only at bootstrap, so the simultaneous strategy's extra queries are cheap and its worst
//! case is one timeout rather than a retry ladder.

use super::*;
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::io;

pub(crate) mod message;
pub(crate) mod transport;

pub(crate) use message::*;
use transport::{exchange, Transport};

/// Per-transmission timeout
pub(crate) const QUERY_TIMEOUT_MS: u32 = 5_000;

/// How the nameservers of one list are asked
// allow, not expect: RESOLUTION_STRATEGY selects one variant, leaving the other unconstructed
#[allow(
    dead_code,
    reason = "both strategies are selectable at RESOLUTION_STRATEGY"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolutionStrategy {
    /// Every nameserver over UDP and TCP at once; the first definitive answer wins and the rest are cancelled
    Simultaneous,
    /// One nameserver at a time in list order, UDP first and TCP only on truncation
    Serial,
}

/// The strategy the resolver uses
pub(crate) const RESOLUTION_STRATEGY: ResolutionStrategy = ResolutionStrategy::Simultaneous;

/// Failure of one lookup, or of one nameserver/transport combination within it
#[derive(Debug)]
pub(crate) enum DnsError {
    InvalidName(&'static str),
    Io(io::Error),
    Timeout,
    Truncated,
    Rcode(u16),
    /// NXDOMAIN, or NOERROR with no answers
    NoRecords {
        rcode: u16,
    },
    Malformed(&'static str),
    NoNameServers,
}

impl DnsError {
    /// A definitive answer from any server ends the lookup; other failures leave the rest in play
    fn is_definitive(&self) -> bool {
        matches!(self, DnsError::NoRecords { .. })
    }

    /// Preference when choosing which of several failures to report
    fn rank(&self) -> u8 {
        match self {
            DnsError::NoNameServers => 0,
            DnsError::Timeout => 1,
            DnsError::Io(_) => 2,
            DnsError::Malformed(_) => 3,
            DnsError::Truncated => 4,
            DnsError::InvalidName(_) => 5,
            DnsError::Rcode(_) => 6,
            DnsError::NoRecords { .. } => 7,
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::InvalidName(what) => write!(f, "invalid name: {}", what),
            DnsError::Io(e) => write!(f, "io: {}", e),
            DnsError::Timeout => write!(f, "timeout"),
            DnsError::Truncated => write!(f, "truncated"),
            DnsError::Rcode(rcode) => write!(f, "{} (rcode {})", rcode_name(*rcode), rcode),
            DnsError::NoRecords { rcode } => write!(f, "no records ({})", rcode_name(*rcode)),
            DnsError::Malformed(what) => write!(f, "malformed: {}", what),
            DnsError::NoNameServers => write!(f, "no nameservers"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<io::Error> for DnsError {
    fn from(e: io::Error) -> Self {
        DnsError::Io(e)
    }
}

fn rcode_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "noerror",
        1 => "formerr",
        2 => "servfail",
        3 => "nxdomain",
        4 => "notimp",
        5 => "refused",
        16 => "badvers",
        _ => "rcode",
    }
}

/// Look up `name`/`qtype` on `servers` with the configured strategy and timeout
pub(crate) async fn query(
    servers: &[SocketAddr],
    name: &str,
    qtype: u16,
) -> Result<Response, DnsError> {
    query_with(servers, name, qtype, RESOLUTION_STRATEGY, QUERY_TIMEOUT_MS).await
}

/// Look up `name`/`qtype` on `servers` with an explicit strategy and per-transmission timeout
pub(crate) async fn query_with(
    servers: &[SocketAddr],
    name: &str,
    qtype: u16,
    strategy: ResolutionStrategy,
    timeout_ms: u32,
) -> Result<Response, DnsError> {
    if servers.is_empty() {
        return Err(DnsError::NoNameServers);
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    match strategy {
        ResolutionStrategy::Simultaneous => {
            query_simultaneous(servers, name, qtype, timeout_ms).await
        }
        ResolutionStrategy::Serial => query_serial(servers, name, qtype, timeout_ms).await,
    }
}

async fn query_simultaneous(
    servers: &[SocketAddr],
    name: &str,
    qtype: u16,
    timeout_ms: u32,
) -> Result<Response, DnsError> {
    let mut unord: FuturesUnordered<PinBoxFuture<'_, Result<Response, DnsError>>> =
        FuturesUnordered::new();
    for &server in servers {
        for transport in [Transport::Udp, Transport::Tcp] {
            unord.push(Box::pin(query_one(
                server, transport, name, qtype, timeout_ms,
            )));
        }
    }
    let mut last = DnsError::NoNameServers;
    while let Some(res) = unord.next().await {
        match res {
            // Dropping the rest closes their sockets and abandons their connects
            Ok(r) => return Ok(r),
            Err(e) if e.is_definitive() => return Err(e),
            Err(e) => {
                if e.rank() >= last.rank() {
                    last = e;
                }
            }
        }
    }
    Err(last)
}

async fn query_serial(
    servers: &[SocketAddr],
    name: &str,
    qtype: u16,
    timeout_ms: u32,
) -> Result<Response, DnsError> {
    let mut last = DnsError::NoNameServers;
    for &server in servers {
        let udp = Box::pin(query_one(server, Transport::Udp, name, qtype, timeout_ms)).await;
        let res = match udp {
            Err(DnsError::Truncated) => {
                Box::pin(query_one(server, Transport::Tcp, name, qtype, timeout_ms)).await
            }
            res => res,
        };
        match res {
            Ok(r) => return Ok(r),
            Err(e) if e.is_definitive() => return Err(e),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn query_one(
    server: SocketAddr,
    transport: Transport,
    name: &str,
    qtype: u16,
    timeout_ms: u32,
) -> Result<Response, DnsError> {
    let id = (get_random_u32() & 0xFFFF) as u16;
    // EDNS keeps the bootstrap answer under the UDP limit; TCP needs no size hint and stays plain
    // so an EDNS-hostile server is still reachable
    let edns = match transport {
        Transport::Udp => Some(EDNS_UDP_PAYLOAD),
        Transport::Tcp => None,
    };
    let query = build_query(id, name, qtype, edns)?;
    let response = exchange(server, transport, &query, id, name, qtype, timeout_ms).await?;
    classify(response)
}

/// Turn a reply into an answer or the failure it represents
pub(crate) fn classify(resp: Response) -> Result<Response, DnsError> {
    if resp.truncated {
        return Err(DnsError::Truncated);
    }
    match resp.rcode {
        RCODE_NOERROR if !resp.answers.is_empty() => Ok(resp),
        RCODE_NOERROR | RCODE_NXDOMAIN => Err(DnsError::NoRecords { rcode: resp.rcode }),
        rcode => Err(DnsError::Rcode(rcode)),
    }
}

/// Each TXT record's character-strings joined into one string; records that are not UTF-8 are dropped
#[must_use]
pub(crate) fn txt_records(resp: &Response) -> Vec<String> {
    resp.answers
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::Txt(strings) => String::from_utf8(strings.concat()).ok(),
            _ => None,
        })
        .collect()
}

/// The first PTR target, without a trailing dot
#[must_use]
pub(crate) fn ptr_record(resp: &Response) -> Option<String> {
    resp.answers.iter().find_map(|rr| match &rr.rdata {
        RData::Ptr(target) => Some(target.trim_end_matches('.').to_string()),
        _ => None,
    })
}
