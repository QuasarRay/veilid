//! Routing Table Health Metrics

use super::*;

/// Externally visible health metrics for the routing table
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct RoutingTableHealth {
    /// Total number of entries in the routing table
    pub total_entry_count: usize,
    /// Number of reliable (long-term responsive) entries in the routing table
    pub reliable_entry_count: usize,
    /// Number of unreliable (occasionally unresponsive) entries in the routing table
    pub unreliable_entry_count: usize,
    /// Number of punished (manually or automatically) entries in the routing table
    pub punished_entry_count: usize,
    /// Number of dead (always unresponsive) entries in the routing table
    pub dead_entry_count: usize,
    /// Health per routing domain
    pub routing_domain_health: HashMap<RoutingDomain, RoutingDomainHealth>,
}

impl RoutingTableHealth {
    /// Number of live entries in the routing table
    #[must_use]
    pub fn live_entry_count(&self) -> usize {
        self.reliable_entry_count + self.unreliable_entry_count
    }

    /// Whether the given routing domain is ready for use for all operations (inbound and outbound)
    #[must_use]
    pub fn routing_domain_ready(&self, routing_domain: RoutingDomain) -> bool {
        self.routing_domain_health
            .get(&routing_domain)
            .map(|h| h.ready())
            .unwrap_or(false)
    }
}

impl fmt::Display for RoutingTableHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            let mut domains_health = Vec::new();

            domains_health.push(format!(
                "all:\n    total={}\n    live={} (reliable={}, unreliable={})\n    dead={}\n    punished={}",
                self.total_entry_count,
                self.live_entry_count(),
                self.reliable_entry_count,
                self.unreliable_entry_count,
                self.dead_entry_count,
                self.punished_entry_count
            ));

            for (rd, h) in self.routing_domain_health.iter() {
                domains_health.push(format!("{:#}:\n{:#}", rd, indent_all_string(h)));
            }
            write!(f, "{}", domains_health.join("\n"))
        } else {
            let mut domains_health = Vec::new();

            domains_health.push(format!(
                "all:[total={}, live={} (reliable={}, unreliable={}), dead={}, punished={}]",
                self.total_entry_count,
                self.live_entry_count(),
                self.reliable_entry_count,
                self.unreliable_entry_count,
                self.dead_entry_count,
                self.punished_entry_count
            ));

            for (rd, h) in self.routing_domain_health.iter() {
                domains_health.push(format!("{}:[{}]", rd, h));
            }
            write!(f, "{}", domains_health.join("\n"))
        }
    }
}
