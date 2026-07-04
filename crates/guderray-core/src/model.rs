//! Proxy profile data model. Each `Outbound` variant maps to a sing-box outbound object.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// A single proxy node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub outbound: Outbound,
    /// Last measured latency in ms (persisted); -2 = unreachable, None = untested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<i32>,
    /// Unix seconds of the last latency test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_test: Option<i64>,
}

impl Profile {
    /// Render this profile as a sing-box outbound object with the given tag.
    pub fn to_singbox(&self, tag: &str) -> Value {
        self.outbound.to_singbox(tag)
    }

    pub fn server_endpoint(&self) -> (String, u16) {
        self.outbound.server_endpoint()
    }
}

// ---------------------------------------------------------------------------
// Shared TLS / transport
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tls {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// uTLS fingerprint, e.g. "chrome".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<Reality>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Reality {
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
}

impl Tls {
    fn to_singbox(&self) -> Value {
        let mut o = Map::new();
        o.insert("enabled".into(), json!(true));
        if let Some(sni) = &self.server_name {
            o.insert("server_name".into(), json!(sni));
        }
        if self.insecure {
            o.insert("insecure".into(), json!(true));
        }
        if !self.alpn.is_empty() {
            o.insert("alpn".into(), json!(self.alpn));
        }
        if let Some(fp) = &self.fingerprint {
            o.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
        }
        if let Some(r) = &self.reality {
            o.insert(
                "reality".into(),
                json!({ "enabled": true, "public_key": r.public_key, "short_id": r.short_id }),
            );
        }
        Value::Object(o)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Transport {
    Ws {
        #[serde(default)]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    Grpc {
        #[serde(default)]
        service_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_timeout: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        permit_without_stream: Option<bool>,
    },
    Http {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        host: Vec<String>,
        #[serde(default)]
        path: String,
    },
    Httpupgrade {
        #[serde(default)]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
}

impl Transport {
    fn to_singbox(&self) -> Value {
        match self {
            Transport::Ws { path, host } => {
                let mut o = json!({ "type": "ws", "path": if path.is_empty() { "/" } else { path } });
                if let Some(h) = host {
                    o["headers"] = json!({ "Host": h });
                }
                o
            }
            Transport::Grpc { service_name, idle_timeout, permit_without_stream } => {
                let mut o = json!({ "type": "grpc", "service_name": service_name });
                if let Some(v) = idle_timeout {
                    o["idle_timeout"] = json!(v);
                }
                if let Some(v) = permit_without_stream {
                    o["permit_without_stream"] = json!(v);
                }
                o
            }
            Transport::Http { host, path } => {
                json!({ "type": "http", "host": host, "path": if path.is_empty() { "/" } else { path } })
            }
            Transport::Httpupgrade { path, host } => {
                let mut o = json!({ "type": "httpupgrade", "path": if path.is_empty() { "/" } else { path } });
                if let Some(h) = host {
                    o["host"] = json!(h);
                }
                o
            }
        }
    }
}

/// TLS + transport shared by vless/vmess/trojan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stream {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
}

impl Stream {
    fn apply(&self, o: &mut Map<String, Value>) {
        if let Some(tls) = &self.tls {
            if tls.enabled {
                o.insert("tls".into(), tls.to_singbox());
            }
        }
        if let Some(tr) = &self.transport {
            o.insert("transport".into(), tr.to_singbox());
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound protocols
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum Outbound {
    Vless(Vless),
    Vmess(Vmess),
    Trojan(Trojan),
    Shadowsocks(Shadowsocks),
    Hysteria2(Hysteria2),
    Tuic(Tuic),
    Socks(Socks),
    Http(Http),
    /// A raw sing-box outbound object (escape hatch for unsupported protocols).
    Raw(RawOutbound),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vless {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub stream: Stream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vmess {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default)]
    pub alter_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(default)]
    pub stream: Stream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trojan {
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default)]
    pub stream: Stream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shadowsocks {
    pub server: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2 {
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tuic {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion_control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawOutbound {
    pub server: String,
    pub port: u16,
    /// A sing-box outbound object (without "tag"; tag is injected on render).
    pub value: Value,
}

impl Outbound {
    pub fn server_endpoint(&self) -> (String, u16) {
        match self {
            Outbound::Vless(v) => (v.server.clone(), v.port),
            Outbound::Vmess(v) => (v.server.clone(), v.port),
            Outbound::Trojan(v) => (v.server.clone(), v.port),
            Outbound::Shadowsocks(v) => (v.server.clone(), v.port),
            Outbound::Hysteria2(v) => (v.server.clone(), v.port),
            Outbound::Tuic(v) => (v.server.clone(), v.port),
            Outbound::Socks(v) => (v.server.clone(), v.port),
            Outbound::Http(v) => (v.server.clone(), v.port),
            Outbound::Raw(v) => (v.server.clone(), v.port),
        }
    }

    pub fn to_singbox(&self, tag: &str) -> Value {
        let mut o = Map::new();
        match self {
            Outbound::Vless(v) => {
                o.insert("type".into(), json!("vless"));
                o.insert("server".into(), json!(v.server));
                o.insert("server_port".into(), json!(v.port));
                o.insert("uuid".into(), json!(v.uuid));
                if let Some(f) = &v.flow {
                    if !f.is_empty() {
                        o.insert("flow".into(), json!(f));
                    }
                }
                o.insert(
                    "packet_encoding".into(),
                    json!(v.packet_encoding.clone().unwrap_or_else(|| "xudp".into())),
                );
                v.stream.apply(&mut o);
            }
            Outbound::Vmess(v) => {
                o.insert("type".into(), json!("vmess"));
                o.insert("server".into(), json!(v.server));
                o.insert("server_port".into(), json!(v.port));
                o.insert("uuid".into(), json!(v.uuid));
                o.insert("alter_id".into(), json!(v.alter_id));
                o.insert(
                    "security".into(),
                    json!(v.security.clone().unwrap_or_else(|| "auto".into())),
                );
                v.stream.apply(&mut o);
            }
            Outbound::Trojan(v) => {
                o.insert("type".into(), json!("trojan"));
                o.insert("server".into(), json!(v.server));
                o.insert("server_port".into(), json!(v.port));
                o.insert("password".into(), json!(v.password));
                v.stream.apply(&mut o);
            }
            Outbound::Shadowsocks(v) => {
                o.insert("type".into(), json!("shadowsocks"));
                o.insert("server".into(), json!(v.server));
                o.insert("server_port".into(), json!(v.port));
                o.insert("method".into(), json!(v.method));
                o.insert("password".into(), json!(v.password));
            }
            Outbound::Hysteria2(v) => {
                o.insert("type".into(), json!("hysteria2"));
                o.insert("server".into(), json!(v.server));
                o.insert("server_port".into(), json!(v.port));
                o.insert("password".into(), json!(v.password));
                if let Some(obfs) = &v.obfs {
                    o.insert(
                        "obfs".into(),
                        json!({ "type": obfs, "password": v.obfs_password.clone().unwrap_or_default() }),
                    );
                }
                let tls = v.tls.clone().unwrap_or(Tls { enabled: true, ..Default::default() });
                o.insert("tls".into(), tls.to_singbox());
            }
            Outbound::Tuic(v) => {
                o.insert("type".into(), json!("tuic"));
                o.insert("server".into(), json!(v.server));
                o.insert("server_port".into(), json!(v.port));
                o.insert("uuid".into(), json!(v.uuid));
                o.insert("password".into(), json!(v.password));
                if let Some(cc) = &v.congestion_control {
                    o.insert("congestion_control".into(), json!(cc));
                }
                let tls = v.tls.clone().unwrap_or(Tls { enabled: true, ..Default::default() });
                o.insert("tls".into(), tls.to_singbox());
            }
            Outbound::Socks(v) => {
                o.insert("type".into(), json!("socks"));
                o.insert("server".into(), json!(v.server));
                o.insert("server_port".into(), json!(v.port));
                o.insert("version".into(), json!("5"));
                if let Some(u) = &v.username {
                    o.insert("username".into(), json!(u));
                }
                if let Some(p) = &v.password {
                    o.insert("password".into(), json!(p));
                }
            }
            Outbound::Http(v) => {
                o.insert("type".into(), json!("http"));
                o.insert("server".into(), json!(v.server));
                o.insert("server_port".into(), json!(v.port));
                if let Some(u) = &v.username {
                    o.insert("username".into(), json!(u));
                }
                if let Some(p) = &v.password {
                    o.insert("password".into(), json!(p));
                }
                if let Some(tls) = &v.tls {
                    if tls.enabled {
                        o.insert("tls".into(), tls.to_singbox());
                    }
                }
            }
            Outbound::Raw(v) => {
                if let Value::Object(m) = &v.value {
                    o = m.clone();
                }
            }
        }
        o.insert("tag".into(), json!(tag));
        Value::Object(o)
    }
}
