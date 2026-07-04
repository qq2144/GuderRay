//! Parse proxy share links into `Outbound`.

use crate::error::{CoreError, Result};
use crate::model::*;
use base64::Engine;
use std::collections::HashMap;

/// Try several base64 alphabets/paddings.
fn b64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for e in engines {
        if let Ok(v) = e.decode(s) {
            return Some(v);
        }
    }
    None
}

fn pct(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

fn query_map(u: &url::Url) -> HashMap<String, String> {
    u.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn name_of(u: &url::Url) -> String {
    u.fragment().map(pct).unwrap_or_default()
}

/// Build a Stream (tls + transport) from URL query params, v2ray-style.
fn stream_from_params(q: &HashMap<String, String>, host_fallback: &str) -> Stream {
    let security = q.get("security").map(|s| s.as_str()).unwrap_or("none");
    let mut tls = None;
    if matches!(security, "tls" | "reality" | "xtls") {
        let sni = q
            .get("sni")
            .or_else(|| q.get("peer"))
            .cloned()
            .unwrap_or_else(|| host_fallback.to_string());
        let alpn = q
            .get("alpn")
            .map(|a| a.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        let insecure = matches!(
            q.get("allowInsecure").or_else(|| q.get("insecure")).map(|s| s.as_str()),
            Some("1") | Some("true")
        );
        let reality = q.get("pbk").filter(|s| !s.is_empty()).map(|pbk| Reality {
            public_key: pbk.clone(),
            short_id: q.get("sid").cloned().unwrap_or_default(),
        });
        tls = Some(Tls {
            enabled: true,
            server_name: Some(sni),
            insecure,
            alpn,
            fingerprint: q.get("fp").filter(|s| !s.is_empty()).cloned(),
            reality,
        });
    }

    let net = q.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let transport = match net {
        "ws" => Some(Transport::Ws {
            path: q.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: q.get("host").filter(|s| !s.is_empty()).cloned(),
        }),
        "grpc" => Some(Transport::Grpc {
            service_name: q.get("serviceName").or_else(|| q.get("service_name")).cloned().unwrap_or_default(),
            idle_timeout: q.get("idle_timeout").or_else(|| q.get("idleTimeout")).cloned(),
            permit_without_stream: q.get("permit_without_stream").or_else(|| q.get("permitWithoutStream")).and_then(|v| match v.as_str() {
                "1" | "true" => Some(true),
                "0" | "false" => Some(false),
                _ => None,
            }),
        }),
        "http" | "h2" => Some(Transport::Http {
            host: q
                .get("host")
                .map(|h| h.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default(),
            path: q.get("path").cloned().unwrap_or_else(|| "/".into()),
        }),
        "httpupgrade" => Some(Transport::Httpupgrade {
            path: q.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: q.get("host").filter(|s| !s.is_empty()).cloned(),
        }),
        _ => None,
    };

    Stream { tls, transport }
}

/// Parse a single share link. Returns (name, outbound).
pub fn parse_link(link: &str) -> Result<(String, Outbound)> {
    let link = link.trim();
    let scheme = link.split("://").next().unwrap_or("").to_lowercase();
    match scheme.as_str() {
        "vless" => parse_vless(link),
        "trojan" => parse_trojan(link),
        "vmess" => parse_vmess(link),
        "ss" => parse_ss(link),
        "hysteria2" | "hy2" => parse_hysteria2(link),
        "tuic" => parse_tuic(link),
        "socks" | "socks5" => parse_socks(link),
        other => Err(CoreError::UnsupportedProtocol(other.to_string())),
    }
}

fn require_host_port(u: &url::Url) -> Result<(String, u16)> {
    let host = u
        .host_str()
        .ok_or_else(|| CoreError::InvalidLink("missing host".into()))?
        .to_string();
    let port = u
        .port()
        .ok_or_else(|| CoreError::InvalidLink("missing port".into()))?;
    Ok((host, port))
}

fn parse_vless(link: &str) -> Result<(String, Outbound)> {
    let u = url::Url::parse(link).map_err(|e| CoreError::InvalidLink(e.to_string()))?;
    let uuid = pct(u.username());
    if uuid.is_empty() {
        return Err(CoreError::InvalidLink("vless: missing uuid".into()));
    }
    let (host, port) = require_host_port(&u)?;
    let q = query_map(&u);
    let stream = stream_from_params(&q, &host);
    let ob = Outbound::Vless(Vless {
        server: host,
        port,
        uuid,
        flow: q.get("flow").filter(|s| !s.is_empty()).cloned(),
        packet_encoding: None,
        stream,
    });
    Ok((name_of(&u), ob))
}

fn parse_trojan(link: &str) -> Result<(String, Outbound)> {
    let u = url::Url::parse(link).map_err(|e| CoreError::InvalidLink(e.to_string()))?;
    let password = pct(u.username());
    let (host, port) = require_host_port(&u)?;
    let q = query_map(&u);
    let mut stream = stream_from_params(&q, &host);
    // trojan defaults to TLS even without security=tls
    if stream.tls.is_none() {
        stream.tls = Some(Tls {
            enabled: true,
            server_name: Some(q.get("sni").cloned().unwrap_or_else(|| host.clone())),
            ..Default::default()
        });
    }
    let ob = Outbound::Trojan(Trojan { server: host, port, password, stream });
    Ok((name_of(&u), ob))
}

fn parse_vmess(link: &str) -> Result<(String, Outbound)> {
    let body = link.strip_prefix("vmess://").unwrap_or(link);
    let raw = b64(body).ok_or_else(|| CoreError::InvalidLink("vmess: bad base64".into()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| CoreError::InvalidLink(format!("vmess json: {e}")))?;
    let gs = |k: &str| v.get(k).map(|x| x.as_str().map(|s| s.to_string()).unwrap_or_else(|| x.to_string()));
    let server = gs("add").ok_or_else(|| CoreError::InvalidLink("vmess: missing add".into()))?;
    let port: u16 = gs("port").and_then(|p| p.parse().ok()).unwrap_or(443);
    let uuid = gs("id").ok_or_else(|| CoreError::InvalidLink("vmess: missing id".into()))?;
    let aid: u32 = gs("aid").and_then(|p| p.parse().ok()).unwrap_or(0);
    let net = gs("net").unwrap_or_else(|| "tcp".into());
    let tls_on = gs("tls").map(|t| t == "tls" || t == "true").unwrap_or(false);

    let tls = if tls_on {
        Some(Tls {
            enabled: true,
            server_name: gs("sni").or_else(|| gs("host")).or(Some(server.clone())),
            alpn: gs("alpn")
                .map(|a| a.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default(),
            fingerprint: gs("fp").filter(|s| !s.is_empty()),
            ..Default::default()
        })
    } else {
        None
    };
    let transport = match net.as_str() {
        "ws" => Some(Transport::Ws {
            path: gs("path").unwrap_or_else(|| "/".into()),
            host: gs("host").filter(|s| !s.is_empty()),
        }),
        "grpc" => Some(Transport::Grpc {
            service_name: gs("path").unwrap_or_default(),
            idle_timeout: gs("idle_timeout").or_else(|| gs("idleTimeout")),
            permit_without_stream: gs("permit_without_stream").or_else(|| gs("permitWithoutStream")).and_then(|v| match v.as_str() {
                "1" | "true" => Some(true),
                "0" | "false" => Some(false),
                _ => None,
            }),
        }),
        "h2" | "http" => Some(Transport::Http {
            host: gs("host").map(|h| vec![h]).unwrap_or_default(),
            path: gs("path").unwrap_or_else(|| "/".into()),
        }),
        _ => None,
    };
    let name = gs("ps").unwrap_or_default();
    let ob = Outbound::Vmess(Vmess {
        server,
        port,
        uuid,
        alter_id: aid,
        security: gs("scy").filter(|s| !s.is_empty()),
        stream: Stream { tls, transport },
    });
    Ok((name, ob))
}

fn parse_ss(link: &str) -> Result<(String, Outbound)> {
    // Two forms: ss://base64(method:pass)@host:port#name  or  ss://base64(method:pass@host:port)#name
    let (main, name) = match link.split_once('#') {
        Some((m, n)) => (m.to_string(), pct(n)),
        None => (link.to_string(), String::new()),
    };
    let body = main.strip_prefix("ss://").unwrap_or(&main);
    // strip any query
    let body = body.split('?').next().unwrap_or(body);

    let (method, password, host, port);
    if let Some((userinfo, hostport)) = body.rsplit_once('@') {
        // userinfo may be base64(method:pass) or plain method:pass
        let creds = b64(userinfo)
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| pct(userinfo));
        let (m, p) = creds
            .split_once(':')
            .ok_or_else(|| CoreError::InvalidLink("ss: bad userinfo".into()))?;
        method = m.to_string();
        password = p.to_string();
        let (h, pt) = hostport
            .rsplit_once(':')
            .ok_or_else(|| CoreError::InvalidLink("ss: bad host:port".into()))?;
        host = h.trim_matches(|c| c == '[' || c == ']').to_string();
        port = pt.parse().map_err(|_| CoreError::InvalidLink("ss: bad port".into()))?;
    } else {
        // fully base64 encoded
        let decoded = b64(body)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| CoreError::InvalidLink("ss: bad base64".into()))?;
        let (userinfo, hostport) = decoded
            .rsplit_once('@')
            .ok_or_else(|| CoreError::InvalidLink("ss: bad format".into()))?;
        let (m, p) = userinfo
            .split_once(':')
            .ok_or_else(|| CoreError::InvalidLink("ss: bad userinfo".into()))?;
        method = m.to_string();
        password = p.to_string();
        let (h, pt) = hostport
            .rsplit_once(':')
            .ok_or_else(|| CoreError::InvalidLink("ss: bad host:port".into()))?;
        host = h.trim_matches(|c| c == '[' || c == ']').to_string();
        port = pt.parse().map_err(|_| CoreError::InvalidLink("ss: bad port".into()))?;
    }

    let ob = Outbound::Shadowsocks(Shadowsocks { server: host, port, method, password });
    Ok((name, ob))
}

fn parse_hysteria2(link: &str) -> Result<(String, Outbound)> {
    let normalized = link.replacen("hy2://", "hysteria2://", 1);
    let u = url::Url::parse(&normalized).map_err(|e| CoreError::InvalidLink(e.to_string()))?;
    let password = if !u.username().is_empty() {
        pct(u.username())
    } else {
        u.password().map(pct).unwrap_or_default()
    };
    let (host, port) = require_host_port(&u)?;
    let q = query_map(&u);
    let tls = Some(Tls {
        enabled: true,
        server_name: q.get("sni").cloned().or(Some(host.clone())),
        insecure: matches!(q.get("insecure").map(|s| s.as_str()), Some("1") | Some("true")),
        ..Default::default()
    });
    let ob = Outbound::Hysteria2(Hysteria2 {
        server: host,
        port,
        password,
        obfs: q.get("obfs").filter(|s| !s.is_empty()).cloned(),
        obfs_password: q.get("obfs-password").cloned(),
        tls,
    });
    Ok((name_of(&u), ob))
}

fn parse_tuic(link: &str) -> Result<(String, Outbound)> {
    let u = url::Url::parse(link).map_err(|e| CoreError::InvalidLink(e.to_string()))?;
    let uuid = pct(u.username());
    let password = u.password().map(pct).unwrap_or_default();
    let (host, port) = require_host_port(&u)?;
    let q = query_map(&u);
    let tls = Some(Tls {
        enabled: true,
        server_name: q.get("sni").cloned().or(Some(host.clone())),
        alpn: q
            .get("alpn")
            .map(|a| a.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default(),
        ..Default::default()
    });
    let ob = Outbound::Tuic(Tuic {
        server: host,
        port,
        uuid,
        password,
        congestion_control: q.get("congestion_control").cloned(),
        tls,
    });
    Ok((name_of(&u), ob))
}

fn parse_socks(link: &str) -> Result<(String, Outbound)> {
    let u = url::Url::parse(link).map_err(|e| CoreError::InvalidLink(e.to_string()))?;
    let (host, port) = require_host_port(&u)?;
    let username = (!u.username().is_empty()).then(|| pct(u.username()));
    let password = u.password().map(pct);
    let ob = Outbound::Socks(Socks { server: host, port, username, password });
    Ok((name_of(&u), ob))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vless_grpc_options() {
        let (_, ob) = parse_link("vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&type=grpc&serviceName=svc&idle_timeout=30s&permit_without_stream=true#node").unwrap();
        match ob {
            Outbound::Vless(v) => match v.stream.transport.unwrap() {
                Transport::Grpc { service_name, idle_timeout, permit_without_stream } => {
                    assert_eq!(service_name, "svc");
                    assert_eq!(idle_timeout.as_deref(), Some("30s"));
                    assert_eq!(permit_without_stream, Some(true));
                }
                _ => panic!("expected grpc"),
            },
            _ => panic!("expected vless"),
        }
    }
}