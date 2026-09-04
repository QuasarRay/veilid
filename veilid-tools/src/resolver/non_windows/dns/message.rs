//! DNS wire format: query building and response parsing for the record types veilid uses.
//!
//! Decoding is defensive: every read is bounds-checked, compression pointers must point
//! strictly backward with a hop cap, and any malformed section rejects the whole message.

use super::*;

/// Fixed header: ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT, all big-endian u16
pub(crate) const HEADER_LEN: usize = 12;

const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE_MASK: u16 = 0x7800;
const FLAG_OPCODE_SHIFT: u16 = 11;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RCODE_MASK: u16 = 0x000F;

const LABEL_KIND_MASK: u8 = 0xC0;
const LABEL_KIND_POINTER: u8 = 0xC0;
const POINTER_OFFSET_MASK: u8 = 0x3F;

pub(crate) const TYPE_PTR: u16 = 12;
pub(crate) const TYPE_TXT: u16 = 16;
pub(crate) const TYPE_OPT: u16 = 41;
pub(crate) const CLASS_IN: u16 = 1;

pub(crate) const RCODE_NOERROR: u16 = 0;
pub(crate) const RCODE_NXDOMAIN: u16 = 3;

pub(crate) const MAX_LABEL_LEN: usize = 63;
pub(crate) const MAX_NAME_LEN: usize = 255;
pub(crate) const MAX_POINTER_HOPS: usize = 16;
/// EDNS0 UDP payload size advertised in queries (RFC 6891 / DNS flag day 2020 value)
pub(crate) const EDNS_UDP_PAYLOAD: u16 = 1232;
/// Receive buffer for a UDP answer; servers may ignore the advertised payload size
pub(crate) const MAX_UDP_MESSAGE_LEN: usize = 4096;

/// A question section entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Record data for the types veilid reads; everything else is skipped
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RData {
    Txt(Vec<Vec<u8>>),
    Ptr(String),
    Other,
}

/// A resource record from any section
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: RData,
}

/// A parsed DNS message
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub truncated: bool,
    /// 12-bit response code including the EDNS extended bits
    pub rcode: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
}

impl Response {
    /// True if this is a reply to the query with `id` for `name`/`qtype`
    #[must_use]
    pub(crate) fn matches(&self, id: u16, name: &str, qtype: u16) -> bool {
        if self.id != id || !self.qr || self.opcode != 0 || self.questions.len() != 1 {
            return false;
        }
        let q = &self.questions[0];
        q.qtype == qtype
            && q.qclass == CLASS_IN
            && q.name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(name.trim_end_matches('.'))
    }
}

/// Append `name` in wire form (length-prefixed labels, root terminator)
pub(crate) fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    if !name.is_ascii() {
        return Err(DnsError::InvalidName("non-ascii"));
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(DnsError::InvalidName("empty name"));
    }
    // Root terminator counts toward the wire length limit
    let mut wire_len = 1;
    for label in name.split('.') {
        if label.is_empty() {
            return Err(DnsError::InvalidName("empty label"));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(DnsError::InvalidName("label too long"));
        }
        wire_len += 1 + label.len();
        if wire_len > MAX_NAME_LEN {
            return Err(DnsError::InvalidName("name too long"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Build a recursion-desired query for `name`/`qtype`, with an EDNS0 OPT record when a UDP payload size is given
pub(crate) fn build_query(
    id: u16,
    name: &str,
    qtype: u16,
    edns_udp_payload: Option<u16>,
) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(HEADER_LEN + MAX_NAME_LEN + 4 + 11);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&u16::from(edns_udp_payload.is_some()).to_be_bytes());
    encode_name(name, &mut out)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    if let Some(payload) = edns_udp_payload {
        // OPT pseudo-record: root name, class carries the payload size, TTL carries version/flags
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&payload.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    Ok(out)
}

/// Parse a complete DNS message
pub(crate) fn parse_response(msg: &[u8]) -> Result<Response, DnsError> {
    if msg.len() < HEADER_LEN {
        return Err(DnsError::Malformed("short header"));
    }
    let id = read_u16(msg, 0)?;
    let flags = read_u16(msg, 2)?;
    let qdcount = read_u16(msg, 4)?;
    let ancount = read_u16(msg, 6)?;
    let nscount = read_u16(msg, 8)?;
    let arcount = read_u16(msg, 10)?;

    let mut pos = HEADER_LEN;
    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let (name, next) = decode_name(msg, pos)?;
        let qtype = read_u16(msg, next)?;
        let qclass = read_u16(msg, next + 2)?;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
        pos = next + 4;
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (rr, next) = parse_rr(msg, pos)?;
        answers.push(rr);
        pos = next;
    }
    for _ in 0..nscount {
        let (_, next) = parse_rr(msg, pos)?;
        pos = next;
    }
    let mut rcode = flags & FLAG_RCODE_MASK;
    for _ in 0..arcount {
        let (rr, next) = parse_rr(msg, pos)?;
        if rr.rtype == TYPE_OPT {
            // Extended rcode lives in the top byte of the OPT TTL
            rcode |= ((rr.ttl >> 24) as u16) << 4;
        }
        pos = next;
    }

    Ok(Response {
        id,
        qr: flags & FLAG_QR != 0,
        opcode: ((flags & FLAG_OPCODE_MASK) >> FLAG_OPCODE_SHIFT) as u8,
        truncated: flags & FLAG_TC != 0,
        rcode,
        questions,
        answers,
    })
}

fn read_u16(msg: &[u8], pos: usize) -> Result<u16, DnsError> {
    let b = msg
        .get(pos..pos + 2)
        .ok_or(DnsError::Malformed("truncated"))?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32(msg: &[u8], pos: usize) -> Result<u32, DnsError> {
    let b = msg
        .get(pos..pos + 4)
        .ok_or(DnsError::Malformed("truncated"))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Decode a possibly compressed name at `start`, returning it with the position after it in the original stream
fn decode_name(msg: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<u8> = Vec::new();
    let mut pos = start;
    let mut end = None;
    let mut hops = 0;
    // Root terminator counts toward the wire length limit
    let mut wire_len = 1;
    loop {
        let len = *msg.get(pos).ok_or(DnsError::Malformed("truncated name"))?;
        match len & LABEL_KIND_MASK {
            0 => {
                if len == 0 {
                    let name = String::from_utf8(labels)
                        .map_err(|_| DnsError::Malformed("non-ascii label"))?;
                    return Ok((name, end.unwrap_or(pos + 1)));
                }
                let len = len as usize;
                wire_len += 1 + len;
                if wire_len > MAX_NAME_LEN {
                    return Err(DnsError::Malformed("name too long"));
                }
                let label = msg
                    .get(pos + 1..pos + 1 + len)
                    .ok_or(DnsError::Malformed("truncated label"))?;
                // Names on the wire are ASCII; unicode arrives punycoded
                if !label.is_ascii() {
                    return Err(DnsError::Malformed("non-ascii label"));
                }
                if !labels.is_empty() {
                    labels.push(b'.');
                }
                labels.extend_from_slice(label);
                pos += 1 + len;
            }
            LABEL_KIND_POINTER => {
                let lo = *msg
                    .get(pos + 1)
                    .ok_or(DnsError::Malformed("truncated pointer"))?;
                let target = (usize::from(len & POINTER_OFFSET_MASK) << 8) | usize::from(lo);
                // Backward-only pointers cannot loop; the hop cap bounds label re-walks
                if target >= pos {
                    return Err(DnsError::Malformed("forward pointer"));
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(DnsError::Malformed("pointer chain too long"));
                }
                if end.is_none() {
                    end = Some(pos + 2);
                }
                pos = target;
            }
            _ => return Err(DnsError::Malformed("label type")),
        }
    }
}

fn parse_rr(msg: &[u8], pos: usize) -> Result<(ResourceRecord, usize), DnsError> {
    let (name, pos) = decode_name(msg, pos)?;
    let rtype = read_u16(msg, pos)?;
    let ttl = read_u32(msg, pos + 4)?;
    let rdlen = usize::from(read_u16(msg, pos + 8)?);
    let rdata_pos = pos + 10;
    let rdata_end = rdata_pos + rdlen;
    let rdata_bytes = msg
        .get(rdata_pos..rdata_end)
        .ok_or(DnsError::Malformed("rdlength"))?;
    let rdata = match rtype {
        TYPE_TXT => RData::Txt(parse_txt(rdata_bytes)?),
        TYPE_PTR => {
            let (target, end) = decode_name(msg, rdata_pos)?;
            if end > rdata_end {
                return Err(DnsError::Malformed("ptr rdata"));
            }
            RData::Ptr(target)
        }
        _ => RData::Other,
    };
    Ok((
        ResourceRecord {
            name,
            rtype,
            ttl,
            rdata,
        },
        rdata_end,
    ))
}

/// TXT rdata is a sequence of length-prefixed character-strings that must exactly tile it
fn parse_txt(rdata: &[u8]) -> Result<Vec<Vec<u8>>, DnsError> {
    let mut strings = Vec::new();
    let mut pos = 0;
    while pos < rdata.len() {
        let len = usize::from(rdata[pos]);
        let s = rdata
            .get(pos + 1..pos + 1 + len)
            .ok_or(DnsError::Malformed("txt rdata"))?;
        strings.push(s.to_vec());
        pos += 1 + len;
    }
    Ok(strings)
}
