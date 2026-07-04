//! Subscription parsing: share-link lists, Clash YAML, sing-box JSON, and SIP008.

use crate::link::parse_link;
use crate::model::*;
use base64::Engine;
use serde_json::Value;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubscriptionParseReport {
    pub nodes: Vec<(String, Outbound)>,
    pub imported: usize,
    pub skipped: usize,
    pub format: String,
}

/// Backward-compatible parser for callers that only need imported nodes.
pub fn parse_subscription(body: &str) -> Vec<(String, Outbound)> {
    parse_subscription_report(body).nodes
}

/// Parse a subscription body, returning imported/skipped counts and detected format.
pub fn parse_subscription_report(body: &str) -> SubscriptionParseReport {
    if let Some(r) = parse_clash_yaml(body) {
        return r;
    }
    if let Some(r) = parse_json_subscription(body) {
        return r;
    }
    parse_link_list(body)
}

fn parse_link_list(body: &str) -> SubscriptionParseReport {
    let text = decode_if_base64(body);
    let mut nodes = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.contains("://") {
            skipped += 1;
            eprintln!("[warn] skipped subscription line without URL scheme: {line}");
            continue;
        }
        match parse_link(line) {
            Ok(pair) => nodes.push(pair),
            Err(e) => {
                skipped += 1;
                eprintln!("[warn] skipped subscription link: {e}");
            }
        }
    }
    let imported = nodes.len();
    SubscriptionParseReport { nodes, imported, skipped, format: "link-list".into() }
}

fn parse_clash_yaml(body: &str) -> Option<SubscriptionParseReport> {
    let doc: serde_yaml::Value = serde_yaml::from_str(body).ok()?;
    let proxies = doc.get("proxies")?.as_sequence()?;
    let mut nodes = Vec::new();
    let mut skipped = 0usize;
    for proxy in proxies {
        match clash_proxy_to_outbound(proxy) {
            Ok(pair) => nodes.push(pair),
            Err(e) => {
                skipped += 1;
                eprintln!("[warn] skipped Clash proxy: {e}");
            }
        }
    }
    let imported = nodes.len();
    Some(SubscriptionParseReport { nodes, imported, skipped, format: "clash-yaml".into() })
}

fn parse_json_subscription(body: &str) -> Option<SubscriptionParseReport> {
    let v: Value = serde_json::from_str(body).ok()?;
    if let Some(outbounds) = v.get("outbounds").and_then(|x| x.as_array()) {
        let mut nodes = Vec::new();
        let mut skipped = 0usize;
        for ob in outbounds {
            match singbox_outbound_to_outbound(ob) {
                Ok(pair) => nodes.push(pair),
                Err(e) => {
                    skipped += 1;
                    eprintln!("[warn] skipped sing-box outbound: {e}");
                }
            }
        }
        let imported = nodes.len();
        return Some(SubscriptionParseReport { nodes, imported, skipped, format: "sing-box-json".into() });
    }
    if let Some(servers) = v.get("servers").and_then(|x| x.as_array()) {
        let mut nodes = Vec::new();
        let mut skipped = 0usize;
        for srv in servers {
            match sip008_server_to_outbound(srv) {
                Ok(pair) => nodes.push(pair),
                Err(e) => {
                    skipped += 1;
                    eprintln!("[warn] skipped SIP008 server: {e}");
                }
            }
        }
        let imported = nodes.len();
        return Some(SubscriptionParseReport { nodes, imported, skipped, format: "sip008-json".into() });
    }
    None
}

pub fn clash_proxy_to_outbound(proxy: &serde_yaml::Value) -> Result<(String, Outbound), String> {
    let name = ystr(proxy, "name").unwrap_or_else(|| "unnamed".into());
    let typ = ystr(proxy, "type").ok_or("missing type")?.to_lowercase();
    let server = ystr(proxy, "server").ok_or("missing server")?;
    let port = yu16(proxy, "port").ok_or("missing port")?;
    let tls = ybool(proxy, "tls").unwrap_or(false);
    let sni = ystr(proxy, "servername").or_else(|| ystr(proxy, "sni"));
    let skip_cert_verify = ybool(proxy, "skip-cert-verify").unwrap_or(false);
    let stream = Stream {
        tls: tls.then(|| Tls {
            enabled: true,
            server_name: sni.clone().or_else(|| Some(server.clone())),
            insecure: skip_cert_verify,
            ..Default::default()
        }),
        transport: clash_network(proxy),
    };
    let outbound = match typ.as_str() {
        "vless" => Outbound::Vless(Vless {
            server,
            port,
            uuid: ystr(proxy, "uuid").ok_or("missing uuid")?,
            flow: ystr(proxy, "flow"),
            packet_encoding: None,
            stream,
        }),
        "vmess" => Outbound::Vmess(Vmess {
            server,
            port,
            uuid: ystr(proxy, "uuid").ok_or("missing uuid")?,
            alter_id: yu32(proxy, "alterId").or_else(|| yu32(proxy, "alter-id")).unwrap_or(0),
            security: ystr(proxy, "cipher"),
            stream,
        }),
        "trojan" => Outbound::Trojan(Trojan {
            server,
            port,
            password: ystr(proxy, "password").ok_or("missing password")?,
            stream,
        }),
        "ss" | "shadowsocks" => Outbound::Shadowsocks(Shadowsocks {
            server,
            port,
            method: ystr(proxy, "cipher").ok_or("missing cipher")?,
            password: ystr(proxy, "password").ok_or("missing password")?,
        }),
        "hysteria2" | "hy2" => Outbound::Hysteria2(Hysteria2 {
            server,
            port,
            password: ystr(proxy, "password").ok_or("missing password")?,
            obfs: ystr(proxy, "obfs"),
            obfs_password: ystr(proxy, "obfs-password"),
            tls: Some(Tls { enabled: true, server_name: sni, insecure: skip_cert_verify, ..Default::default() }),
        }),
        "tuic" => Outbound::Tuic(Tuic {
            server,
            port,
            uuid: ystr(proxy, "uuid").ok_or("missing uuid")?,
            password: ystr(proxy, "password").ok_or("missing password")?,
            congestion_control: ystr(proxy, "congestion-controller").or_else(|| ystr(proxy, "congestion_control")),
            tls: Some(Tls { enabled: true, server_name: sni, insecure: skip_cert_verify, ..Default::default() }),
        }),
        "socks5" | "socks" => Outbound::Socks(Socks { server, port, username: ystr(proxy, "username"), password: ystr(proxy, "password") }),
        "http" => Outbound::Http(Http { server, port, username: ystr(proxy, "username"), password: ystr(proxy, "password"), tls: None }),
        other => return Err(format!("unsupported Clash proxy type: {other}")),
    };
    Ok((name, outbound))
}

fn clash_network(proxy: &serde_yaml::Value) -> Option<Transport> {
    match ystr(proxy, "network").unwrap_or_default().as_str() {
        "ws" => Some(Transport::Ws { path: ystr(proxy, "ws-path").or_else(|| ystr(proxy, "path")).unwrap_or_else(|| "/".into()), host: ystr(proxy, "ws-headers.Host").or_else(|| ystr(proxy, "host")) }),
        "grpc" => Some(Transport::Grpc { service_name: ystr(proxy, "grpc-service-name").or_else(|| ystr(proxy, "serviceName")).unwrap_or_default(), idle_timeout: ystr(proxy, "idle_timeout"), permit_without_stream: ybool(proxy, "permit_without_stream") }),
        "h2" | "http" => Some(Transport::Http { host: ystr(proxy, "host").map(|h| vec![h]).unwrap_or_default(), path: ystr(proxy, "path").unwrap_or_else(|| "/".into()) }),
        "httpupgrade" => Some(Transport::Httpupgrade { path: ystr(proxy, "path").unwrap_or_else(|| "/".into()), host: ystr(proxy, "host") }),
        _ => None,
    }
}

fn singbox_outbound_to_outbound(v: &Value) -> Result<(String, Outbound), String> {
    let tag = v.get("tag").and_then(Value::as_str).unwrap_or("unnamed").to_string();
    let _typ = v.get("type").and_then(Value::as_str).ok_or("missing type")?.to_string();
    let server = v.get("server").and_then(Value::as_str).unwrap_or_default().to_string();
    let port = v.get("server_port").and_then(Value::as_u64).unwrap_or(0) as u16;
    if server.is_empty() || port == 0 {
        return Err("missing server/server_port".into());
    }
    let mut raw = v.clone();
    if let Value::Object(m) = &mut raw {
        m.remove("tag");
    }
    Ok((tag, Outbound::Raw(RawOutbound { server, port, value: raw })))
}

fn sip008_server_to_outbound(v: &Value) -> Result<(String, Outbound), String> {
    let server = jstr(v, "server").ok_or("missing server")?;
    let port = v.get("server_port").or_else(|| v.get("port")).and_then(Value::as_u64).ok_or("missing port")? as u16;
    let method = jstr(v, "method").ok_or("missing method")?;
    let password = jstr(v, "password").ok_or("missing password")?;
    let name = jstr(v, "remarks").or_else(|| jstr(v, "name")).unwrap_or_else(|| server.clone());
    Ok((name, Outbound::Shadowsocks(Shadowsocks { server, port, method, password })))
}

fn ystr(v: &serde_yaml::Value, key: &str) -> Option<String> {
    let mut cur = v;
    for part in key.split('.') {
        cur = cur.get(part)?;
    }
    cur.as_str().map(|s| s.to_string()).or_else(|| cur.as_i64().map(|n| n.to_string()))
}
fn ybool(v: &serde_yaml::Value, key: &str) -> Option<bool> { v.get(key)?.as_bool() }
fn yu16(v: &serde_yaml::Value, key: &str) -> Option<u16> { v.get(key)?.as_i64().and_then(|n| u16::try_from(n).ok()) }
fn yu32(v: &serde_yaml::Value, key: &str) -> Option<u32> { v.get(key)?.as_i64().and_then(|n| u32::try_from(n).ok()) }
fn jstr(v: &Value, key: &str) -> Option<String> { v.get(key)?.as_str().map(|s| s.to_string()) }

/// If the whole body looks like base64 of a link list, decode it; else return as-is.
fn decode_if_base64(body: &str) -> String {
    let trimmed: String = body.split_whitespace().collect();
    if trimmed.contains("://") {
        return body.to_string();
    }
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for e in engines {
        if let Ok(bytes) = e.decode(trimmed.as_bytes()) {
            if let Ok(s) = String::from_utf8(bytes) {
                if s.contains("://") {
                    return s;
                }
            }
        }
    }
    body.to_string()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clash_yaml_subscription() {
        let body = r#"
proxies:
  - name: ss-node
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass
"#;
        let report = parse_subscription_report(body);
        assert_eq!(report.format, "clash-yaml");
        assert_eq!(report.imported, 1);
        assert_eq!(report.skipped, 0);
    }

    #[test]
    fn parse_singbox_and_sip008_json() {
        let sing = r#"{"outbounds":[{"type":"shadowsocks","tag":"raw","server":"example.com","server_port":8388,"method":"aes-128-gcm","password":"p"}]}"#;
        assert_eq!(parse_subscription_report(sing).format, "sing-box-json");
        let sip = r#"{"servers":[{"remarks":"sip","server":"example.com","server_port":8388,"method":"aes-128-gcm","password":"p"}]}"#;
        assert_eq!(parse_subscription_report(sip).format, "sip008-json");
    }
}