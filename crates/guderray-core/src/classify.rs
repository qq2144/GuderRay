//! Read-only interpretation of already-routed traffic and preview classification of
//! not-yet-routed domains. Deliberately separate from `routing.rs`, which owns
//! compiling/persisting the rule model — this module only *reads* things.

use crate::routing::{RoutingMode, UserRules};

/// Classify an already-established connection's route (direct/proxy/block) from the
/// Clash API's `chains` array — the sequence of outbound tags sing-box actually used.
///
/// Verified against a real running node before writing this (not guessed from docs):
/// `chains` for a cn-direct-routed connection is `["direct"]`, for the proxy catch-all
/// it's `["proxy"]` — the last element is always our own outbound tag. `rule` is a
/// free-form human-readable description of *which* rule matched (e.g.
/// `"rule_set=[geosite-cn geosite-geolocation-cn] => route(direct)"` or plain `"final"`)
/// and varies with the exact rule_set/custom-rule that fired, so it's not something to
/// pattern-match on for classification — `chains` is the stable signal. `rule` is kept
/// as a parameter for callers that want to display it, and as a defensive fallback.
///
/// Note: blocked connections were observed to close in ~0ms (sing-box's reject outbound
/// completes before any `/connections` poll can observe them) — in practice the "block"
/// arm here is rarely if ever exercised by a live connection list, only by historical/
/// synthetic data. It's kept for correctness since the outbound tag is still "block" if
/// one ever is captured.
pub fn classify_connection(rule: &str, chains: &[String]) -> &'static str {
    match chains.last().map(String::as_str) {
        Some("direct") => "direct",
        Some("block") => "block",
        Some("proxy") => "proxy",
        _ => {
            // No recognizable chain (shouldn't normally happen) — fall back to a crude
            // scan of the rule text rather than silently guessing "proxy" outright.
            if rule.contains("block") {
                "block"
            } else if rule.contains("direct") {
                "direct"
            } else {
                "proxy"
            }
        }
    }
}

/// Does a `RuleList.domains` entry match `domain`? Mirrors `compile_domains`'s own
/// prefix parsing (routing.rs) exactly, so classification agrees with what `build_config`
/// would actually compile — bare entries and `domain:` both suffix-match (matching
/// `compile_domains`'s `domain_suffix` semantics: exact host or any subdomain).
fn domain_matches(list: &[String], domain: &str) -> bool {
    let domain = domain.to_lowercase();
    list.iter().any(|raw| {
        let item = raw.trim();
        if item.is_empty() || item.starts_with('#') {
            return false;
        }
        if let Some(v) = item.strip_prefix("full:") {
            domain == v.to_lowercase()
        } else if let Some(v) = item.strip_prefix("domain:") {
            let v = v.to_lowercase();
            domain == v || domain.ends_with(&format!(".{v}"))
        } else if let Some(v) = item.strip_prefix("keyword:") {
            domain.contains(&v.to_lowercase())
        } else if item.starts_with("regexp:") || item.starts_with("geosite:") {
            // No local regex engine or geosite rule-set data client-side — these can't
            // be verified for the live preview even though they're valid in the user's
            // own list (build_config still compiles and uses them for real routing).
            false
        } else {
            let v = item.to_lowercase();
            domain == v || domain.ends_with(&format!(".{v}"))
        }
    })
}

/// Preview-classify a domain the way the Rules view's live preview does, mirroring
/// `build_config`'s real route-rule precedence (config.rs): user block > user proxy >
/// user direct > (CnDirect mode only) a crude ".cn"-suffix heuristic > fallback proxy.
///
/// Honesty note, surfaced in the UI (not just here): this client has no local geosite/
/// geoip rule-set data (those are remote `.srs` files sing-box fetches and matches
/// internally), so `geosite:`/`regexp:` entries in the user's own rules can't be
/// verified by this preview, and the CnDirect heuristic is a crude approximation of
/// the real geosite-cn/geosite-geolocation-cn rule-sets — not a guarantee of what a
/// live connection will actually do. That's what the real-node E2E check is for.
pub fn classify_domain(rules: &UserRules, routing: RoutingMode, domain: &str) -> &'static str {
    if domain_matches(&rules.block.domains, domain) {
        return "block";
    }
    if domain_matches(&rules.proxy.domains, domain) {
        return "proxy";
    }
    if domain_matches(&rules.direct.domains, domain) {
        return "direct";
    }
    if routing == RoutingMode::CnDirect {
        let d = domain.to_lowercase();
        if d == "cn" || d.ends_with(".cn") {
            return "direct";
        }
    }
    "proxy"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_chain_classifies_as_direct() {
        assert_eq!(
            classify_connection(
                "rule_set=[geosite-cn geosite-geolocation-cn] => route(direct)",
                &["direct".to_string()]
            ),
            "direct"
        );
    }

    #[test]
    fn proxy_final_chain_classifies_as_proxy() {
        assert_eq!(classify_connection("final", &["proxy".to_string()]), "proxy");
    }

    #[test]
    fn block_chain_classifies_as_block() {
        assert_eq!(classify_connection("route(block)", &["block".to_string()]), "block");
    }

    #[test]
    fn empty_chain_falls_back_to_rule_text_scan() {
        assert_eq!(classify_connection("route(direct)", &[]), "direct");
        assert_eq!(classify_connection("route(block)", &[]), "block");
        assert_eq!(classify_connection("final", &[]), "proxy");
    }

    #[test]
    fn multi_hop_chain_uses_the_last_hop() {
        // e.g. a selector/urltest group in front of the real outbound
        assert_eq!(classify_connection("final", &["auto".to_string(), "proxy".to_string()]), "proxy");
    }

    fn rules_with(block: &[&str], proxy: &[&str], direct: &[&str]) -> UserRules {
        use crate::routing::RuleList;
        let to_vec = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect();
        UserRules {
            block: RuleList { domains: to_vec(block), ..Default::default() },
            proxy: RuleList { domains: to_vec(proxy), ..Default::default() },
            direct: RuleList { domains: to_vec(direct), ..Default::default() },
        }
    }

    #[test]
    fn block_wins_over_proxy_and_direct_for_the_same_domain() {
        let rules = rules_with(&["ads.example.com"], &["ads.example.com"], &["ads.example.com"]);
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "ads.example.com"), "block");
    }

    #[test]
    fn proxy_wins_over_direct_for_the_same_domain() {
        let rules = rules_with(&[], &["chatgpt.com"], &["chatgpt.com"]);
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "chatgpt.com"), "proxy");
    }

    #[test]
    fn full_prefix_matches_exactly_not_subdomains() {
        let rules = rules_with(&[], &[], &["full:example.com"]);
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "example.com"), "direct");
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "www.example.com"), "proxy");
    }

    #[test]
    fn domain_prefix_matches_exact_and_subdomains() {
        let rules = rules_with(&[], &[], &["domain:example.com"]);
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "example.com"), "direct");
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "www.example.com"), "direct");
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "notexample.com"), "proxy");
    }

    #[test]
    fn keyword_prefix_matches_a_substring_anywhere() {
        let rules = rules_with(&[], &[], &["keyword:ads"]);
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "ads.example.com"), "direct");
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "myads.example.com"), "direct");
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "example.com"), "proxy");
    }

    #[test]
    fn bare_entry_falls_back_to_suffix_matching() {
        let rules = rules_with(&[], &[], &["example.cn"]);
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "example.cn"), "direct");
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "sub.example.cn"), "direct");
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "notexample.cn"), "proxy");
    }

    #[test]
    fn cn_suffix_heuristic_only_applies_in_cn_direct_mode() {
        let rules = rules_with(&[], &[], &[]);
        assert_eq!(classify_domain(&rules, RoutingMode::CnDirect, "baidu.cn"), "direct");
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "baidu.cn"), "proxy");
        assert_eq!(classify_domain(&rules, RoutingMode::Custom, "baidu.cn"), "proxy");
    }

    #[test]
    fn no_match_falls_back_to_proxy() {
        let rules = rules_with(&[], &[], &[]);
        assert_eq!(classify_domain(&rules, RoutingMode::Global, "example.com"), "proxy");
        assert_eq!(classify_domain(&rules, RoutingMode::CnDirect, "example.com"), "proxy");
    }
}
