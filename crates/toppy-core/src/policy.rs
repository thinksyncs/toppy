use ipnet::IpNet;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PolicyConfig {
    pub allow: Vec<PolicyRuleConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PolicyRuleConfig {
    pub cidr: String,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub subjects: Vec<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    cidr: IpNet,
    ports: Vec<u16>,
    subjects: Vec<String>,
    claims: BTreeMap<String, Vec<String>>,
}

impl PolicyRule {
    pub fn parse(
        cidr: &str,
        ports: Vec<u16>,
        subjects: Vec<String>,
        claims: BTreeMap<String, Vec<String>>,
    ) -> Result<Self, String> {
        if ports.is_empty() {
            return Err("ports must not be empty".to_string());
        }
        if subjects.iter().any(|subject| subject.trim().is_empty()) {
            return Err("subjects must not contain empty values".to_string());
        }
        for (claim, values) in &claims {
            if claim.trim().is_empty() {
                return Err("claim names must not be empty".to_string());
            }
            if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
                return Err(format!("claim {} must contain non-empty values", claim));
            }
        }
        let cidr = cidr
            .parse::<IpNet>()
            .map_err(|e| format!("invalid cidr {}: {}", cidr, e))?;
        Ok(Self {
            cidr,
            ports,
            subjects,
            claims,
        })
    }

    fn matches(&self, target: &Target) -> bool {
        self.network_matches(target)
            && self.subject_matches(target)
            && self.claims_match(target)
    }

    fn network_matches(&self, target: &Target) -> bool {
        self.cidr.contains(&target.ip) && self.ports.contains(&target.port)
    }

    fn subject_matches(&self, target: &Target) -> bool {
        self.subjects.is_empty()
            || target
                .subject
                .as_ref()
                .is_some_and(|subject| self.subjects.iter().any(|allowed| allowed == subject))
    }

    fn claims_match(&self, target: &Target) -> bool {
        self.claims.iter().all(|(claim, allowed_values)| {
            target
                .claims
                .get(claim)
                .is_some_and(|value| allowed_values.iter().any(|allowed| allowed == value))
        })
    }

    fn mismatch_reason(&self, target: &Target) -> Option<String> {
        if !self.network_matches(target) {
            return None;
        }
        if !self.subject_matches(target) {
            return Some(match target.subject.as_deref() {
                Some(subject) => format!("subject {} not allowed for {}:{}", subject, target.ip, target.port),
                None => format!("subject required for {}:{}", target.ip, target.port),
            });
        }
        for (claim, allowed_values) in &self.claims {
            match target.claims.get(claim) {
                Some(value) if allowed_values.iter().any(|allowed| allowed == value) => {}
                Some(value) => {
                    return Some(format!(
                        "claim {}={} not allowed for {}:{}",
                        claim, value, target.ip, target.port
                    ))
                }
                None => {
                    return Some(format!(
                        "claim {} required for {}:{}",
                        claim, target.ip, target.port
                    ))
                }
            }
        }
        None
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
    pub subject: Option<String>,
    pub claims: BTreeMap<String, String>,
}

impl Target {
    pub fn parse(ip: &str, port: u16) -> Result<Self, String> {
        let ip = ip
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid ip {}: {}", ip, e))?;
        Ok(Self {
            ip,
            port,
            subject: None,
            claims: BTreeMap::new(),
        })
    }

    pub fn with_auth(mut self, subject: Option<String>, claims: BTreeMap<String, String>) -> Self {
        self.subject = subject;
        self.claims = claims;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

impl Policy {
    pub fn from_config(cfg: &PolicyConfig) -> Result<Self, String> {
        let mut allow = Vec::with_capacity(cfg.allow.len());
        for rule in &cfg.allow {
            allow.push(PolicyRule::parse(
                &rule.cidr,
                rule.ports.clone(),
                rule.subjects.clone(),
                rule.claims.clone(),
            )?);
        }
        Ok(Self { allow })
    }

    pub fn evaluate(&self, target: &Target) -> Decision {
        let mut auth_mismatch: Option<String> = None;
        for rule in &self.allow {
            if rule.matches(target) {
                return Decision::Allow;
            }
            if auth_mismatch.is_none() {
                auth_mismatch = rule.mismatch_reason(target);
            }
        }
        if let Some(reason) = auth_mismatch {
            return Decision::Deny { reason };
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
        let rule = PolicyRule::parse("10.0.0.0/24", vec![22, 443], Vec::new(), BTreeMap::new())
            .expect("rule");
        let policy = Policy { allow: vec![rule] };
        let target = Target::parse("10.0.0.5", 22).expect("target");
        assert_eq!(policy.evaluate(&target), Decision::Allow);
    }

    #[test]
    fn policy_denies_unlisted_port() {
        let rule = PolicyRule::parse("10.0.0.0/24", vec![22], Vec::new(), BTreeMap::new())
            .expect("rule");
        let policy = Policy { allow: vec![rule] };
        let target = Target::parse("10.0.0.5", 443).expect("target");
        assert!(matches!(policy.evaluate(&target), Decision::Deny { .. }));
    }

    #[test]
    fn policy_denies_outside_cidr() {
        let rule = PolicyRule::parse("10.0.0.0/24", vec![22], Vec::new(), BTreeMap::new())
            .expect("rule");
        let policy = Policy { allow: vec![rule] };
        let target = Target::parse("10.0.1.5", 22).expect("target");
        assert!(matches!(policy.evaluate(&target), Decision::Deny { .. }));
    }

    #[test]
    fn policy_rejects_empty_ports() {
        let err = PolicyRule::parse("10.0.0.0/24", vec![], Vec::new(), BTreeMap::new())
            .unwrap_err();
        assert!(err.contains("ports"));
    }

    #[test]
    fn policy_from_config_builds_rules() {
        let cfg = PolicyConfig {
            allow: vec![PolicyRuleConfig {
                cidr: "10.0.0.0/24".to_string(),
                ports: vec![22, 443],
                subjects: Vec::new(),
                claims: BTreeMap::new(),
            }],
        };
        let policy = Policy::from_config(&cfg).expect("policy");
        let target = Target::parse("10.0.0.5", 443).expect("target");
        assert_eq!(policy.evaluate(&target), Decision::Allow);
    }

    #[test]
    fn policy_from_config_rejects_empty_ports() {
        let cfg = PolicyConfig {
            allow: vec![PolicyRuleConfig {
                cidr: "10.0.0.0/24".to_string(),
                ports: vec![],
                subjects: Vec::new(),
                claims: BTreeMap::new(),
            }],
        };
        let err = Policy::from_config(&cfg).unwrap_err();
        assert!(err.contains("ports"));
    }

    #[test]
    fn policy_allows_matching_subject_and_claims() {
        let mut claims = BTreeMap::new();
        claims.insert("role".to_string(), vec!["admin".to_string()]);

        let cfg = PolicyConfig {
            allow: vec![PolicyRuleConfig {
                cidr: "10.0.0.0/24".to_string(),
                ports: vec![443],
                subjects: vec!["user-123".to_string()],
                claims,
            }],
        };

        let mut target_claims = BTreeMap::new();
        target_claims.insert("role".to_string(), "admin".to_string());
        let target = Target::parse("10.0.0.5", 443)
            .expect("target")
            .with_auth(Some("user-123".to_string()), target_claims);

        let policy = Policy::from_config(&cfg).expect("policy");
        assert_eq!(policy.evaluate(&target), Decision::Allow);
    }

    #[test]
    fn policy_denies_missing_subject_when_rule_requires_it() {
        let cfg = PolicyConfig {
            allow: vec![PolicyRuleConfig {
                cidr: "10.0.0.0/24".to_string(),
                ports: vec![443],
                subjects: vec!["user-123".to_string()],
                claims: BTreeMap::new(),
            }],
        };

        let target = Target::parse("10.0.0.5", 443).expect("target");
        let policy = Policy::from_config(&cfg).expect("policy");
        let decision = policy.evaluate(&target);

        assert!(matches!(decision, Decision::Deny { ref reason } if reason.contains("subject required")));
    }
}
