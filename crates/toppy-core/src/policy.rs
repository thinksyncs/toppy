use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    cidr: IpNet,
    ports: Vec<u16>,
}

impl PolicyRule {
    pub fn parse(cidr: &str, ports: Vec<u16>) -> Result<Self, String> {
        if ports.is_empty() {
            return Err("ports must not be empty".to_string());
        }
        let cidr = cidr
            .parse::<IpNet>()
            .map_err(|e| format!("invalid cidr {}: {}", cidr, e))?;
        Ok(Self { cidr, ports })
    }

    fn matches(&self, target: &Target) -> bool {
        self.cidr.contains(&target.ip) && self.ports.contains(&target.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub allow: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
}

impl Target {
    pub fn parse(ip: &str, port: u16) -> Result<Self, String> {
        let ip = ip
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid ip {}: {}", ip, e))?;
        Ok(Self { ip, port })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

impl Policy {
    pub fn evaluate(&self, target: &Target) -> Decision {
        for rule in &self.allow {
            if rule.matches(target) {
                return Decision::Allow;
            }
        }
        Decision::Deny {
            reason: format!("target {}:{} not allowed", target.ip, target.port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_allows_matching_target() {
        let rule = PolicyRule::parse("10.0.0.0/24", vec![22, 443]).expect("rule");
        let policy = Policy { allow: vec![rule] };
        let target = Target::parse("10.0.0.5", 22).expect("target");
        assert_eq!(policy.evaluate(&target), Decision::Allow);
    }

    #[test]
    fn policy_denies_unlisted_port() {
        let rule = PolicyRule::parse("10.0.0.0/24", vec![22]).expect("rule");
        let policy = Policy { allow: vec![rule] };
        let target = Target::parse("10.0.0.5", 443).expect("target");
        assert!(matches!(policy.evaluate(&target), Decision::Deny { .. }));
    }

    #[test]
    fn policy_denies_outside_cidr() {
        let rule = PolicyRule::parse("10.0.0.0/24", vec![22]).expect("rule");
        let policy = Policy { allow: vec![rule] };
        let target = Target::parse("10.0.1.5", 22).expect("target");
        assert!(matches!(policy.evaluate(&target), Decision::Deny { .. }));
    }

    #[test]
    fn policy_rejects_empty_ports() {
        let err = PolicyRule::parse("10.0.0.0/24", vec![]).unwrap_err();
        assert!(err.contains("ports"));
    }
}
