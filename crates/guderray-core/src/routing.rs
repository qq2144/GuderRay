//! Routing modes + the unified rule model that compiles domain / IP / process
//! entries into the correct sing-box rule fields, hiding the L3-vs-L7 distinction.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingMode {
    /// Everything through the proxy.
    Global,
    /// China domains/IPs direct, the rest through the proxy.
    CnDirect,
    /// Only user rules + final; no built-in cn rule-sets.
    Custom,
}

impl Default for RoutingMode {
    fn default() -> Self {
        RoutingMode::CnDirect
    }
}

/// A bucket of matchers for one decision (direct / proxy / block).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleList {
    /// Domain entries, optionally prefixed: geosite:/domain:/full:/keyword:/regexp:.
    #[serde(default)]
    pub domains: Vec<String>,
    /// IP entries: geoip:xx or a CIDR / bare IP.
    #[serde(default)]
    pub ips: Vec<String>,
    /// Process names (e.g. wechat.exe).
    #[serde(default)]
    pub processes: Vec<String>,
}

impl RuleList {
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ips.is_empty() && self.processes.is_empty()
    }

    /// Render as one editable entry per line (processes prefixed `process:`).
    pub fn to_lines(&self) -> String {
        let mut out: Vec<String> = Vec::new();
        out.extend(self.domains.iter().cloned());
        out.extend(self.ips.iter().cloned());
        out.extend(self.processes.iter().map(|p| format!("process:{p}")));
        out.join("\n")
    }

    /// Parse editable text back into a RuleList, auto-classifying each line into
    /// domain / IP / process (hiding the L3-vs-L7 distinction from the user).
    pub fn from_lines(text: &str) -> RuleList {
        let mut rl = RuleList::default();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(p) = line.strip_prefix("process:") {
                rl.processes.push(p.trim().to_string());
            } else if line.starts_with("geoip:") {
                rl.ips.push(line.to_string());
            } else if line.starts_with("geosite:")
                || line.starts_with("domain:")
                || line.starts_with("full:")
                || line.starts_with("keyword:")
                || line.starts_with("regexp:")
            {
                rl.domains.push(line.to_string());
            } else if looks_like_ip_or_cidr(line) {
                rl.ips.push(line.to_string());
            } else {
                rl.domains.push(line.to_string());
            }
        }
        rl
    }
}

/// Heuristic: a bare IP, a CIDR, or an IPv6 literal.
fn looks_like_ip_or_cidr(s: &str) -> bool {
    let head = s.split('/').next().unwrap_or(s);
    head.parse::<std::net::IpAddr>().is_ok()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserRules {
    #[serde(default)]
    pub direct: RuleList,
    #[serde(default)]
    pub proxy: RuleList,
    #[serde(default)]
    pub block: RuleList,
}

impl UserRules {
    pub fn is_empty(&self) -> bool {
        self.direct.is_empty() && self.proxy.is_empty() && self.block.is_empty()
    }
}

/// Compile domain entries into sing-box domain matcher fields.
/// Returns an object like { "domain_suffix": [...], "geosite": [...], ... }.
pub fn compile_domains(list: &[String]) -> Map<String, Value> {
    let mut domain = Vec::new();
    let mut suffix = Vec::new();
    let mut keyword = Vec::new();
    let mut regex = Vec::new();
    let mut geosite = Vec::new();
    for raw in list {
        let item = raw.trim();
        if item.is_empty() || item.starts_with('#') {
            continue;
        }
        if let Some(v) = item.strip_prefix("geosite:") {
            geosite.push(v.to_string());
        } else if let Some(v) = item.strip_prefix("full:") {
            domain.push(v.to_lowercase());
        } else if let Some(v) = item.strip_prefix("domain:") {
            suffix.push(v.to_lowercase());
        } else if let Some(v) = item.strip_prefix("keyword:") {
            keyword.push(v.to_lowercase());
        } else if let Some(v) = item.strip_prefix("regexp:") {
            regex.push(v.to_string());
        } else {
            suffix.push(item.to_lowercase());
        }
    }
    let mut o = Map::new();
    if !domain.is_empty() {
        o.insert("domain".into(), json!(domain));
    }
    if !suffix.is_empty() {
        o.insert("domain_suffix".into(), json!(suffix));
    }
    if !keyword.is_empty() {
        o.insert("domain_keyword".into(), json!(keyword));
    }
    if !regex.is_empty() {
        o.insert("domain_regex".into(), json!(regex));
    }
    if !geosite.is_empty() {
        // rule_set references; caller wires these tags into route.rule_set
        o.insert("__geosite".into(), json!(geosite));
    }
    o
}

/// Compile IP entries into sing-box ip matcher fields.
pub fn compile_ips(list: &[String]) -> Map<String, Value> {
    let mut ip_cidr = Vec::new();
    let mut geoip = Vec::new();
    for raw in list {
        let item = raw.trim();
        if item.is_empty() || item.starts_with('#') {
            continue;
        }
        if let Some(v) = item.strip_prefix("geoip:") {
            geoip.push(v.to_string());
        } else {
            ip_cidr.push(item.to_string());
        }
    }
    let mut o = Map::new();
    if !ip_cidr.is_empty() {
        o.insert("ip_cidr".into(), json!(ip_cidr));
    }
    if !geoip.is_empty() {
        o.insert("__geoip".into(), json!(geoip));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_list_lines_roundtrip_and_classify() {
        let rules = RuleList::from_lines("example.com\n1.1.1.1/32\ngeoip:cn\nprocess:wechat.exe\n# ignored");
        assert_eq!(rules.domains, vec!["example.com"]);
        assert_eq!(rules.ips, vec!["1.1.1.1/32", "geoip:cn"]);
        assert_eq!(rules.processes, vec!["wechat.exe"]);
        let lines = rules.to_lines();
        assert!(lines.contains("example.com"));
        assert!(lines.contains("process:wechat.exe"));
    }
}