//! Generate a complete sing-box config from a profile + options.
//! Targets sing-box >= 1.12 (new typed DNS servers, rule actions, remote rule-sets).

use crate::model::Profile;
use crate::routing::{compile_domains, compile_ips, RoutingMode, RuleList, UserRules};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const PROXY_TAG: &str = "proxy";

#[derive(Debug, Clone)]
pub struct GenOptions {
    pub routing: RoutingMode,
    pub user_rules: UserRules,
    pub tun: bool,
    pub tun_stack: String,
    pub tun_mtu: u32,
    pub tun_strict_route: bool,
    pub socks_port: u16,
    pub socks_listen: String,
    pub clash_api_port: u16,
    pub clash_api_secret: String,
    pub direct_dns: String,
    pub remote_dns: String,
    pub dns_strategy: String,
    pub log_level: String,
    pub block_ads: bool,
    pub geosite_base: String,
    pub geoip_base: String,
    pub download_detour: String,
    pub cache_path: Option<String>,
    /// Directory holding pre-downloaded `<tag>.srs` files; if a tag exists there,
    /// a local rule-set entry is emitted instead of a remote one.
    pub local_ruleset_dir: Option<String>,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions {
            routing: RoutingMode::CnDirect,
            user_rules: UserRules::default(),
            tun: false,
            tun_stack: "mixed".into(),
            tun_mtu: 9000,
            tun_strict_route: false,
            socks_port: 2080,
            socks_listen: "127.0.0.1".into(),
            clash_api_port: 9090,
            clash_api_secret: String::new(),
            // DoH-by-IP: immune to plaintext port-53 hijacking and needs no bootstrap
            direct_dns: "https://223.5.5.5/dns-query".into(),
            remote_dns: "https://8.8.8.8/dns-query".into(),
            dns_strategy: "prefer_ipv4".into(),
            log_level: "info".into(),
            block_ads: true,
            geosite_base: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set".into(),
            geoip_base: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set".into(),
            download_detour: PROXY_TAG.into(),
            cache_path: None,
            local_ruleset_dir: None,
        }
    }
}

/// The decision a rule bucket compiles to: an outbound route or a reject action.
enum Decision<'a> {
    Outbound(&'a str),
    Reject,
}

impl Decision<'_> {
    fn apply(&self, o: &mut Map<String, Value>) {
        match self {
            Decision::Outbound(tag) => {
                o.insert("outbound".into(), json!(tag));
            }
            Decision::Reject => {
                o.insert("action".into(), json!("reject"));
            }
        }
    }
}

/// Emit sing-box route rules for one decision bucket, registering any needed rule-sets.
fn emit_rules(decision: &Decision, list: &RuleList, reg: &mut BTreeSet<String>) -> Vec<Value> {
    let mut rules = Vec::new();
    let mut push = |mut matcher: Map<String, Value>| {
        decision.apply(&mut matcher);
        rules.push(Value::Object(matcher));
    };

    // domains
    let mut dm = compile_domains(&list.domains);
    let geosite = dm.remove("__geosite");
    if !dm.is_empty() {
        push(dm);
    }
    if let Some(Value::Array(cats)) = geosite {
        let tags: Vec<String> = cats
            .iter()
            .filter_map(|c| c.as_str())
            .map(|c| format!("geosite-{c}"))
            .collect();
        for t in &tags {
            reg.insert(t.clone());
        }
        let mut m = Map::new();
        m.insert("rule_set".into(), json!(tags));
        push(m);
    }

    // ips
    let mut im = compile_ips(&list.ips);
    let geoip = im.remove("__geoip");
    if !im.is_empty() {
        push(im);
    }
    if let Some(Value::Array(codes)) = geoip {
        let tags: Vec<String> = codes
            .iter()
            .filter_map(|c| c.as_str())
            .map(|c| format!("geoip-{c}"))
            .collect();
        for t in &tags {
            reg.insert(t.clone());
        }
        let mut m = Map::new();
        m.insert("rule_set".into(), json!(tags));
        push(m);
    }

    // processes
    if !list.processes.is_empty() {
        let mut m = Map::new();
        m.insert("process_name".into(), json!(list.processes));
        push(m);
    }

    rules
}

fn ruleset_entry(tag: &str, opt: &GenOptions) -> Value {
    // prefer a locally cached .srs (works before the proxy is reachable)
    if let Some(dir) = &opt.local_ruleset_dir {
        let path = std::path::Path::new(dir).join(format!("{tag}.srs"));
        if path.exists() {
            return json!({
                "type": "local",
                "tag": tag,
                "format": "binary",
                "path": path.to_string_lossy().replace('\\', "/"),
            });
        }
    }
    let base = if tag.starts_with("geosite-") {
        &opt.geosite_base
    } else {
        &opt.geoip_base
    };
    json!({
        "type": "remote",
        "tag": tag,
        "format": "binary",
        "url": format!("{base}/{tag}.srs"),
        "download_detour": opt.download_detour,
        "update_interval": "7d",
    })
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Convert a DNS address string (legacy style) into a sing-box 1.12+ typed server.
/// Supports: "local", bare IP, udp://, tcp://, tls://, https://, h3://, quic://.
fn dns_server(tag: &str, addr: &str, detour: Option<&str>) -> Value {
    let mut o = Map::new();
    o.insert("tag".into(), json!(tag));

    let addr = addr.trim();
    if addr == "local" || addr.is_empty() {
        o.insert("type".into(), json!("local"));
        return Value::Object(o);
    }

    let (scheme, rest) = match addr.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => ("udp".into(), addr),
    };

    // split host[:port][/path]
    let (hostport, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, Some(format!("/{p}"))),
        None => (rest, None),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.is_empty() => {
            (h.trim_matches(|c| c == '[' || c == ']'), p.parse::<u16>().ok())
        }
        _ => (hostport.trim_matches(|c| c == '[' || c == ']'), None),
    };

    let ty = match scheme.as_str() {
        "https" | "h3" | "quic" | "tls" | "tcp" | "udp" => scheme.as_str(),
        _ => "udp",
    };
    o.insert("type".into(), json!(ty));
    o.insert("server".into(), json!(host));
    if let Some(p) = port {
        o.insert("server_port".into(), json!(p));
    }
    if ty == "https" || ty == "h3" {
        if let Some(p) = path {
            if p != "/dns-query" {
                o.insert("path".into(), json!(p));
            }
        }
    }
    if let Some(d) = detour {
        o.insert("detour".into(), json!(d));
    }
    // Domain-name servers need a bootstrap resolver.
    if !is_ip_literal(host) {
        o.insert("domain_resolver".into(), json!("dns-local"));
    }
    Value::Object(o)
}

pub fn build_config(profile: &Profile, opt: &GenOptions) -> Value {
    let mut reg: BTreeSet<String> = BTreeSet::new();

    // -- inbounds --
    let mut inbounds = vec![json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": opt.socks_listen,
        "listen_port": opt.socks_port,
    })];
    if opt.tun {
        inbounds.push(json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "guderray-tun",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": opt.tun_mtu,
            "auto_route": true,
            "strict_route": opt.tun_strict_route,
            "stack": opt.tun_stack,
        }));
    }

    // -- outbounds -- (block/dns outbounds are gone in 1.12+; replaced by rule actions)
    let outbounds = vec![
        profile.to_singbox(PROXY_TAG),
        json!({ "type": "direct", "tag": "direct" }),
    ];

    // -- route rules --
    let mut rules: Vec<Value> = Vec::new();
    // restore domains for all inbounds, then hijack DNS
    rules.push(json!({ "action": "sniff" }));
    rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));

    // user rules first (highest precedence, after security basics)
    rules.extend(emit_rules(&Decision::Reject, &opt.user_rules.block, &mut reg));
    rules.extend(emit_rules(&Decision::Outbound(PROXY_TAG), &opt.user_rules.proxy, &mut reg));
    rules.extend(emit_rules(&Decision::Outbound("direct"), &opt.user_rules.direct, &mut reg));

    // built-in cn-direct
    if opt.routing == RoutingMode::CnDirect {
        for t in ["geosite-cn", "geosite-geolocation-cn", "geoip-cn"] {
            reg.insert(t.to_string());
        }
        rules.push(json!({
            "rule_set": ["geosite-cn", "geosite-geolocation-cn"],
            "outbound": "direct",
        }));
        rules.push(json!({ "rule_set": ["geoip-cn"], "outbound": "direct" }));
        if opt.block_ads {
            reg.insert("geosite-category-ads-all".to_string());
            rules.push(json!({ "rule_set": ["geosite-category-ads-all"], "action": "reject" }));
        }
    }

    // -- dns (1.12+ typed servers) --
    // note: sing-box 1.12+ rejects `detour: "direct"` on DNS servers (direct is implicit)
    let dns_servers = vec![
        dns_server("dns-remote", &opt.remote_dns, Some(PROXY_TAG)),
        dns_server("dns-direct", &opt.direct_dns, None),
        json!({ "tag": "dns-local", "type": "local" }),
    ];
    let mut dns_rules: Vec<Value> = Vec::new();
    if opt.routing == RoutingMode::CnDirect {
        dns_rules.push(json!({ "rule_set": ["geosite-cn"], "server": "dns-direct" }));
    }
    // user direct domains also resolve via direct DNS
    {
        let mut dm = compile_domains(&opt.user_rules.direct.domains);
        let geosite = dm.remove("__geosite");
        if !dm.is_empty() {
            dm.insert("server".into(), json!("dns-direct"));
            dns_rules.push(Value::Object(dm));
        }
        if let Some(Value::Array(cats)) = geosite {
            let tags: Vec<String> = cats
                .iter()
                .filter_map(|c| c.as_str())
                .map(|c| format!("geosite-{c}"))
                .collect();
            for t in &tags {
                reg.insert(t.clone());
            }
            dns_rules.push(json!({ "rule_set": tags, "server": "dns-direct" }));
        }
    }
    // user block domains get NXDOMAIN at the DNS layer too
    {
        let mut dm = compile_domains(&opt.user_rules.block.domains);
        dm.remove("__geosite");
        if !dm.is_empty() {
            dm.insert("action".into(), json!("predefined"));
            dm.insert("rcode".into(), json!("NXDOMAIN"));
            dns_rules.push(Value::Object(dm));
        }
    }
    let dns = json!({
        "servers": dns_servers,
        "rules": dns_rules,
        "final": "dns-remote",
        "strategy": opt.dns_strategy,
        "independent_cache": true,
    });

    // -- rule_set entries --
    let rule_set: Vec<Value> = reg.iter().map(|t| ruleset_entry(t, opt)).collect();

    // default_domain_resolver picks a DNS *server* directly (dns.rules do not apply).
    // Use the DoH-by-IP direct server: hijack-proof and loop-free (no proxy detour).
    let route = json!({
        "rules": rules,
        "rule_set": rule_set,
        "final": PROXY_TAG,
        "auto_detect_interface": true,
        "default_domain_resolver": { "server": "dns-direct" },
    });

    // -- experimental --
    let mut experimental = Map::new();
    experimental.insert(
        "clash_api".into(),
        json!({
            "external_controller": format!("127.0.0.1:{}", opt.clash_api_port),
            "secret": opt.clash_api_secret,
        }),
    );
    if let Some(path) = &opt.cache_path {
        experimental.insert(
            "cache_file".into(),
            json!({ "enabled": true, "path": path }),
        );
    }

    json!({
        "log": { "level": opt.log_level, "timestamp": true },
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
        "experimental": Value::Object(experimental),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Outbound, Profile, Shadowsocks};

    fn sample_profile() -> Profile {
        Profile {
            id: 1,
            name: "t".into(),
            group: None,
            outbound: Outbound::Shadowsocks(Shadowsocks {
                server: "1.2.3.4".into(),
                port: 8388,
                method: "aes-256-gcm".into(),
                password: "p".into(),
            }),
            latency: None,
            last_test: None,
        }
    }

    #[test]
    fn cn_direct_config_has_expected_shape() {
        let opt = GenOptions::default(); // RoutingMode::CnDirect
        let c = build_config(&sample_profile(), &opt);

        // proxy + direct outbounds present, proxy tagged "proxy"
        let obs = c["outbounds"].as_array().unwrap();
        assert!(obs.iter().any(|o| o["tag"] == "proxy"));
        assert!(obs.iter().any(|o| o["tag"] == "direct"));

        // route: final -> proxy, and a geosite-cn rule_set routed to direct
        assert_eq!(c["route"]["final"], "proxy");
        let rules = c["route"]["rules"].as_array().unwrap();
        let cn_direct = rules.iter().any(|r| {
            r["outbound"] == "direct"
                && r["rule_set"]
                    .as_array()
                    .map(|a| a.iter().any(|t| t == "geosite-cn"))
                    .unwrap_or(false)
        });
        assert!(cn_direct, "expected a geosite-cn -> direct rule");

        // rule_set registry includes geoip-cn + geosite-cn
        let rs: Vec<_> = c["route"]["rule_set"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["tag"].as_str().unwrap().to_string())
            .collect();
        assert!(rs.contains(&"geosite-cn".to_string()));
        assert!(rs.contains(&"geoip-cn".to_string()));

        // clash api configured
        assert!(c["experimental"]["clash_api"]["external_controller"].is_string());

        // no tun inbound by default
        let ins = c["inbounds"].as_array().unwrap();
        assert!(ins.iter().all(|i| i["type"] != "tun"));
    }

    #[test]
    fn tun_inbound_added_when_enabled() {
        let mut opt = GenOptions::default();
        opt.tun = true;
        let c = build_config(&sample_profile(), &opt);
        let ins = c["inbounds"].as_array().unwrap();
        assert!(ins.iter().any(|i| i["type"] == "tun"));
    }

    #[test]
    fn global_mode_has_no_cn_ruleset() {
        let mut opt = GenOptions::default();
        opt.routing = crate::routing::RoutingMode::Global;
        let c = build_config(&sample_profile(), &opt);
        let rs = c["route"]["rule_set"].as_array().unwrap();
        assert!(rs.iter().all(|e| e["tag"] != "geosite-cn"));
    }
}
