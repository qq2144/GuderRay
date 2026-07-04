//! Flat, UI-shaped view of `Outbound` for the Nodes editor. A single form with
//! protocol-gated field groups needs a flat struct (one field per possible input), not
//! the tagged-enum shape `Outbound` uses internally — this module is the two-way mapping
//! between them, kept in core (not the GUI crate) so it's covered by the same test
//! discipline as the rest of the model and is reachable from a future CLI `profile edit`
//! form if one is ever added.

use crate::model::{
    Http, Hysteria2, Outbound, Reality, Shadowsocks, Socks, Stream, Tls, Transport, Trojan,
    Tuic, Vless, Vmess,
};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct OutboundDraft {
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    pub flow: String,
    pub packet_encoding: String,
    pub alter_id: u32,
    pub security: String,
    pub method: String,
    pub obfs: String,
    pub obfs_password: String,
    pub congestion_control: String,
    pub username: String,
    pub tls_enabled: bool,
    pub sni: String,
    pub insecure: bool,
    pub alpn: String,
    pub fingerprint: String,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub transport_type: String,
    pub ws_path: String,
    pub ws_host: String,
    pub grpc_service_name: String,
    pub http_host: String,
    pub http_path: String,
    pub httpupgrade_path: String,
    pub httpupgrade_host: String,
}

fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Comma-separated list <-> `Vec<String>`, used for `alpn` and http-transport `host`.
fn split_csv(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect()
}

fn tls_from_draft(d: &OutboundDraft) -> Tls {
    Tls {
        enabled: true,
        server_name: opt(&d.sni),
        insecure: d.insecure,
        alpn: split_csv(&d.alpn),
        fingerprint: opt(&d.fingerprint),
        reality: opt(&d.reality_public_key)
            .map(|public_key| Reality { public_key, short_id: d.reality_short_id.clone() }),
    }
}

fn tls_to_draft(d: &mut OutboundDraft, tls: &Tls) {
    d.tls_enabled = tls.enabled;
    d.sni = tls.server_name.clone().unwrap_or_default();
    d.insecure = tls.insecure;
    d.alpn = tls.alpn.join(",");
    d.fingerprint = tls.fingerprint.clone().unwrap_or_default();
    if let Some(r) = &tls.reality {
        d.reality_public_key = r.public_key.clone();
        d.reality_short_id = r.short_id.clone();
    }
}

fn transport_from_draft(d: &OutboundDraft) -> Option<Transport> {
    match d.transport_type.as_str() {
        "ws" => Some(Transport::Ws { path: d.ws_path.clone(), host: opt(&d.ws_host) }),
        // idle_timeout/permit_without_stream are advanced gRPC knobs not exposed by this
        // flat editor (WS1 added them to the model for subscription import fidelity, not
        // for hand-editing) — round-tripping a node that has them set will drop them.
        "grpc" => Some(Transport::Grpc {
            service_name: d.grpc_service_name.clone(),
            idle_timeout: None,
            permit_without_stream: None,
        }),
        "http" => Some(Transport::Http { host: split_csv(&d.http_host), path: d.http_path.clone() }),
        "httpupgrade" => {
            Some(Transport::Httpupgrade { path: d.httpupgrade_path.clone(), host: opt(&d.httpupgrade_host) })
        }
        _ => None,
    }
}

fn transport_to_draft(d: &mut OutboundDraft, t: &Transport) {
    match t {
        Transport::Ws { path, host } => {
            d.transport_type = "ws".into();
            d.ws_path = path.clone();
            d.ws_host = host.clone().unwrap_or_default();
        }
        Transport::Grpc { service_name, .. } => {
            d.transport_type = "grpc".into();
            d.grpc_service_name = service_name.clone();
        }
        Transport::Http { host, path } => {
            d.transport_type = "http".into();
            d.http_host = host.join(",");
            d.http_path = path.clone();
        }
        Transport::Httpupgrade { path, host } => {
            d.transport_type = "httpupgrade".into();
            d.httpupgrade_path = path.clone();
            d.httpupgrade_host = host.clone().unwrap_or_default();
        }
    }
}

/// Flatten an `Outbound` into its editable draft form. Fields the protocol doesn't use
/// are left at their zero value — `draft_to_outbound` only ever reads the fields the
/// target protocol actually declares, so stale values from a previously-edited protocol
/// can't leak into the wrong output (see the `switching_protocol_does_not_leak_fields`
/// adversarial test below).
pub fn outbound_to_draft(o: &Outbound) -> OutboundDraft {
    let mut d = OutboundDraft::default();
    match o {
        Outbound::Vless(v) => {
            d.protocol = "vless".into();
            d.server = v.server.clone();
            d.port = v.port;
            d.uuid = v.uuid.clone();
            d.flow = v.flow.clone().unwrap_or_default();
            d.packet_encoding = v.packet_encoding.clone().unwrap_or_default();
            if let Some(tls) = &v.stream.tls {
                tls_to_draft(&mut d, tls);
            }
            if let Some(t) = &v.stream.transport {
                transport_to_draft(&mut d, t);
            }
        }
        Outbound::Vmess(v) => {
            d.protocol = "vmess".into();
            d.server = v.server.clone();
            d.port = v.port;
            d.uuid = v.uuid.clone();
            d.alter_id = v.alter_id;
            d.security = v.security.clone().unwrap_or_default();
            if let Some(tls) = &v.stream.tls {
                tls_to_draft(&mut d, tls);
            }
            if let Some(t) = &v.stream.transport {
                transport_to_draft(&mut d, t);
            }
        }
        Outbound::Trojan(v) => {
            d.protocol = "trojan".into();
            d.server = v.server.clone();
            d.port = v.port;
            d.password = v.password.clone();
            if let Some(tls) = &v.stream.tls {
                tls_to_draft(&mut d, tls);
            }
            if let Some(t) = &v.stream.transport {
                transport_to_draft(&mut d, t);
            }
        }
        Outbound::Shadowsocks(v) => {
            d.protocol = "shadowsocks".into();
            d.server = v.server.clone();
            d.port = v.port;
            d.method = v.method.clone();
            d.password = v.password.clone();
        }
        Outbound::Hysteria2(v) => {
            d.protocol = "hysteria2".into();
            d.server = v.server.clone();
            d.port = v.port;
            d.password = v.password.clone();
            d.obfs = v.obfs.clone().unwrap_or_default();
            d.obfs_password = v.obfs_password.clone().unwrap_or_default();
            let tls = v.tls.clone().unwrap_or(Tls { enabled: true, ..Default::default() });
            tls_to_draft(&mut d, &tls);
        }
        Outbound::Tuic(v) => {
            d.protocol = "tuic".into();
            d.server = v.server.clone();
            d.port = v.port;
            d.uuid = v.uuid.clone();
            d.password = v.password.clone();
            d.congestion_control = v.congestion_control.clone().unwrap_or_default();
            let tls = v.tls.clone().unwrap_or(Tls { enabled: true, ..Default::default() });
            tls_to_draft(&mut d, &tls);
        }
        Outbound::Socks(v) => {
            d.protocol = "socks".into();
            d.server = v.server.clone();
            d.port = v.port;
            d.username = v.username.clone().unwrap_or_default();
            d.password = v.password.clone().unwrap_or_default();
        }
        Outbound::Http(v) => {
            d.protocol = "http".into();
            d.server = v.server.clone();
            d.port = v.port;
            d.username = v.username.clone().unwrap_or_default();
            d.password = v.password.clone().unwrap_or_default();
            if let Some(tls) = &v.tls {
                tls_to_draft(&mut d, tls);
            }
        }
        Outbound::Raw(v) => {
            // Escape-hatch protocol: arbitrary sing-box JSON doesn't fit a flat form.
            // The Nodes UI must treat protocol == "raw" as view-only, never call
            // draft_to_outbound on it (which correctly errors if it's tried anyway).
            d.protocol = "raw".into();
            d.server = v.server.clone();
            d.port = v.port;
        }
    }
    d
}

/// Build an `Outbound` from a draft. Errors (not panics) on missing required fields so
/// the GUI can show a validation message instead of crashing on a half-filled form.
pub fn draft_to_outbound(d: &OutboundDraft) -> Result<Outbound, String> {
    if d.server.trim().is_empty() {
        return Err("server is required".into());
    }
    if d.port == 0 {
        return Err("port is required".into());
    }
    let stream = || Stream {
        tls: if d.tls_enabled { Some(tls_from_draft(d)) } else { None },
        transport: transport_from_draft(d),
    };
    match d.protocol.as_str() {
        "vless" => {
            if d.uuid.trim().is_empty() {
                return Err("uuid is required for vless".into());
            }
            Ok(Outbound::Vless(Vless {
                server: d.server.clone(),
                port: d.port,
                uuid: d.uuid.clone(),
                flow: opt(&d.flow),
                packet_encoding: opt(&d.packet_encoding),
                stream: stream(),
            }))
        }
        "vmess" => {
            if d.uuid.trim().is_empty() {
                return Err("uuid is required for vmess".into());
            }
            Ok(Outbound::Vmess(Vmess {
                server: d.server.clone(),
                port: d.port,
                uuid: d.uuid.clone(),
                alter_id: d.alter_id,
                security: opt(&d.security),
                stream: stream(),
            }))
        }
        "trojan" => {
            if d.password.trim().is_empty() {
                return Err("password is required for trojan".into());
            }
            Ok(Outbound::Trojan(Trojan {
                server: d.server.clone(),
                port: d.port,
                password: d.password.clone(),
                stream: stream(),
            }))
        }
        "shadowsocks" => {
            if d.method.trim().is_empty() {
                return Err("method is required for shadowsocks".into());
            }
            if d.password.trim().is_empty() {
                return Err("password is required for shadowsocks".into());
            }
            Ok(Outbound::Shadowsocks(Shadowsocks {
                server: d.server.clone(),
                port: d.port,
                method: d.method.clone(),
                password: d.password.clone(),
            }))
        }
        "hysteria2" => {
            if d.password.trim().is_empty() {
                return Err("password is required for hysteria2".into());
            }
            Ok(Outbound::Hysteria2(Hysteria2 {
                server: d.server.clone(),
                port: d.port,
                password: d.password.clone(),
                obfs: opt(&d.obfs),
                obfs_password: opt(&d.obfs_password),
                tls: Some(tls_from_draft(d)),
            }))
        }
        "tuic" => {
            if d.uuid.trim().is_empty() {
                return Err("uuid is required for tuic".into());
            }
            if d.password.trim().is_empty() {
                return Err("password is required for tuic".into());
            }
            Ok(Outbound::Tuic(Tuic {
                server: d.server.clone(),
                port: d.port,
                uuid: d.uuid.clone(),
                password: d.password.clone(),
                congestion_control: opt(&d.congestion_control),
                tls: Some(tls_from_draft(d)),
            }))
        }
        "socks" => Ok(Outbound::Socks(Socks {
            server: d.server.clone(),
            port: d.port,
            username: opt(&d.username),
            password: opt(&d.password),
        })),
        "http" => Ok(Outbound::Http(Http {
            server: d.server.clone(),
            port: d.port,
            username: opt(&d.username),
            password: opt(&d.password),
            tls: if d.tls_enabled { Some(tls_from_draft(d)) } else { None },
        })),
        other => Err(format!("unsupported or non-editable protocol: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_matches_singbox_json(o: Outbound) {
        let before = o.to_singbox("test");
        let draft = outbound_to_draft(&o);
        let o2 = draft_to_outbound(&draft).expect("draft should convert back cleanly");
        let after = o2.to_singbox("test");
        assert_eq!(before, after, "protocol={}", draft.protocol);
    }

    #[test]
    fn vless_reality_vision_roundtrips() {
        roundtrip_matches_singbox_json(Outbound::Vless(Vless {
            server: "1.2.3.4".into(),
            port: 443,
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            flow: Some("xtls-rprx-vision".into()),
            packet_encoding: Some("xudp".into()),
            stream: Stream {
                tls: Some(Tls {
                    enabled: true,
                    server_name: Some("www.nvidia.com".into()),
                    insecure: false,
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    fingerprint: Some("chrome".into()),
                    reality: Some(Reality { public_key: "pk123".into(), short_id: "abcd".into() }),
                }),
                transport: None,
            },
        }));
    }

    #[test]
    fn vmess_ws_tls_roundtrips() {
        roundtrip_matches_singbox_json(Outbound::Vmess(Vmess {
            server: "vmess.example.com".into(),
            port: 8443,
            uuid: "22222222-2222-2222-2222-222222222222".into(),
            alter_id: 0,
            security: Some("auto".into()),
            stream: Stream {
                tls: Some(Tls { enabled: true, server_name: Some("vmess.example.com".into()), ..Default::default() }),
                transport: Some(Transport::Ws { path: "/ws".into(), host: Some("vmess.example.com".into()) }),
            },
        }));
    }

    #[test]
    fn trojan_grpc_roundtrips() {
        roundtrip_matches_singbox_json(Outbound::Trojan(Trojan {
            server: "trojan.example.com".into(),
            port: 443,
            password: "hunter2".into(),
            stream: Stream {
                tls: Some(Tls { enabled: true, ..Default::default() }),
                transport: Some(Transport::Grpc {
                    service_name: "grpc-svc".into(),
                    idle_timeout: None,
                    permit_without_stream: None,
                }),
            },
        }));
    }

    #[test]
    fn shadowsocks_roundtrips() {
        roundtrip_matches_singbox_json(Outbound::Shadowsocks(Shadowsocks {
            server: "ss.example.com".into(),
            port: 8388,
            method: "aes-256-gcm".into(),
            password: "secret".into(),
        }));
    }

    #[test]
    fn hysteria2_obfs_roundtrips() {
        roundtrip_matches_singbox_json(Outbound::Hysteria2(Hysteria2 {
            server: "hy2.example.com".into(),
            port: 34443,
            password: "hy2pass".into(),
            obfs: Some("salamander".into()),
            obfs_password: Some("obfspass".into()),
            tls: Some(Tls { enabled: true, server_name: Some("hy2.example.com".into()), insecure: true, ..Default::default() }),
        }));
    }

    #[test]
    fn tuic_roundtrips() {
        roundtrip_matches_singbox_json(Outbound::Tuic(Tuic {
            server: "tuic.example.com".into(),
            port: 34443,
            uuid: "33333333-3333-3333-3333-333333333333".into(),
            password: "tuicpass".into(),
            congestion_control: Some("bbr".into()),
            tls: Some(Tls { enabled: true, ..Default::default() }),
        }));
    }

    #[test]
    fn socks_with_auth_roundtrips() {
        roundtrip_matches_singbox_json(Outbound::Socks(Socks {
            server: "socks.example.com".into(),
            port: 1080,
            username: Some("user".into()),
            password: Some("pass".into()),
        }));
    }

    #[test]
    fn http_with_tls_roundtrips() {
        roundtrip_matches_singbox_json(Outbound::Http(Http {
            server: "http.example.com".into(),
            port: 8080,
            username: Some("user".into()),
            password: Some("pass".into()),
            tls: Some(Tls { enabled: true, server_name: Some("http.example.com".into()), ..Default::default() }),
        }));
    }

    #[test]
    fn switching_protocol_does_not_leak_fields_into_singbox_json() {
        let mut d = OutboundDraft {
            protocol: "vless".into(),
            server: "1.2.3.4".into(),
            port: 443,
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            flow: "xtls-rprx-vision".into(),
            tls_enabled: true,
            sni: "www.nvidia.com".into(),
            reality_public_key: "pk123".into(),
            reality_short_id: "abcd".into(),
            transport_type: "ws".into(),
            ws_path: "/ws".into(),
            ws_host: "example.com".into(),
            ..Default::default()
        };
        // now "switch" the same draft to shadowsocks without clearing the vless-only fields
        d.protocol = "shadowsocks".into();
        d.method = "aes-256-gcm".into();
        d.password = "secret".into();

        let o = draft_to_outbound(&d).expect("shadowsocks with method+password is valid");
        let json = o.to_singbox("test");
        let obj = json.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, vec!["method", "password", "server", "server_port", "tag", "type"]);
        assert_eq!(obj["method"], "aes-256-gcm");
        assert_eq!(obj["password"], "secret");
    }

    #[test]
    fn missing_required_field_is_an_error_not_a_panic() {
        let d = OutboundDraft { protocol: "vless".into(), server: "1.2.3.4".into(), port: 443, ..Default::default() };
        assert!(draft_to_outbound(&d).is_err(), "vless without a uuid must error, not panic or silently default");

        let d = OutboundDraft { protocol: "vless".into(), uuid: "x".into(), port: 443, ..Default::default() };
        assert!(draft_to_outbound(&d).is_err(), "empty server must error");

        let d = OutboundDraft { protocol: "vless".into(), server: "1.2.3.4".into(), uuid: "x".into(), ..Default::default() };
        assert!(draft_to_outbound(&d).is_err(), "zero port must error");

        let d = OutboundDraft { protocol: "not-a-real-protocol".into(), server: "1.2.3.4".into(), port: 443, ..Default::default() };
        assert!(draft_to_outbound(&d).is_err(), "unknown protocol must error");
    }
}
