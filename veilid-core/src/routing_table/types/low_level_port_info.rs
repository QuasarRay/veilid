use super::*;

pub type LowLevelProtocolPort = (LowLevelProtocolType, AddressType, u16);
pub type LowLevelProtocolPorts = BTreeSet<LowLevelProtocolPort>;
pub type ProtocolToPortMapping = BTreeMap<(ProtocolType, AddressType), (LowLevelProtocolType, u16)>;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
#[must_use]
pub struct LowLevelPortInfo {
    pub low_level_protocol_ports: LowLevelProtocolPorts,
    pub protocol_to_port: ProtocolToPortMapping,
}

impl fmt::Display for LowLevelPortInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ports: [{}]\nMapping: [{}]",
            self.low_level_protocol_ports
                .iter()
                .map(|(pt, at, p)| format!("{}:{}:{}", f.to_string(pt), f.to_string(at), p))
                .collect::<Vec<_>>()
                .join(", "),
            self.protocol_to_port
                .iter()
                .map(|((pt, at), (lpt, p))| format!(
                    "{}:{}->{}:{}",
                    f.to_string(pt),
                    f.to_string(at),
                    f.to_string(lpt),
                    p
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}
