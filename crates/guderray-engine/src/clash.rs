//! Minimal Clash API (sing-box external controller) REST client.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::time::Duration;

pub struct Clash {
    base: String,
    secret: String,
    agent: ureq::Agent,
}

impl Clash {
    pub fn new(port: u16, secret: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_millis(1500))
            .timeout(Duration::from_secs(20))
            .build();
        Clash {
            base: format!("http://127.0.0.1:{port}"),
            secret: secret.to_string(),
            agent,
        }
    }

    fn get(&self, path: &str) -> ureq::Request {
        let mut req = self.agent.get(&format!("{}{}", self.base, path));
        if !self.secret.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.secret));
        }
        req
    }

    fn delete(&self, path: &str) -> ureq::Request {
        let mut req = self.agent.delete(&format!("{}{}", self.base, path));
        if !self.secret.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.secret));
        }
        req
    }

    pub fn version(&self) -> Result<String> {
        let v: Value = self
            .get("/version")
            .call()
            .context("clash api unreachable")?
            .into_json()?;
        Ok(v["version"].as_str().unwrap_or("unknown").to_string())
    }

    /// Full /connections payload: totals + active connection list.
    pub fn connections(&self) -> Result<Value> {
        Ok(self
            .get("/connections")
            .call()
            .context("clash api unreachable")?
            .into_json()?)
    }

    /// Close one active connection by its Clash API id (`DELETE /connections/{id}`).
    /// Verified against a real running node: `/connections` entries carry a top-level
    /// `id` (a UUID string) that `guderray_engine::connections()` previously dropped.
    pub fn close_connection(&self, id: &str) -> Result<Value> {
        let path = format!("/connections/{}", urlencode(id));
        match self.delete(&path).call() {
            Ok(_) => Ok(Value::Null),
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                Err(anyhow!("close connection failed (http {code}): {body}"))
            }
            Err(e) => Err(anyhow!("clash api unreachable: {e}")),
        }
    }

    /// Close every active connection (`DELETE /connections`).
    pub fn close_all_connections(&self) -> Result<Value> {
        match self.delete("/connections").call() {
            Ok(_) => Ok(Value::Null),
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                Err(anyhow!("close all connections failed (http {code}): {body}"))
            }
            Err(e) => Err(anyhow!("clash api unreachable: {e}")),
        }
    }

    /// URL-test a proxy (our outbound tag is "proxy"). Returns latency ms.
    pub fn delay(&self, proxy: &str, url: &str, timeout_ms: u32) -> Result<u32> {
        let path = format!(
            "/proxies/{}/delay?timeout={}&url={}",
            proxy,
            timeout_ms,
            urlencode(url)
        );
        let resp = self.get(&path).call();
        match resp {
            Ok(r) => {
                let v: Value = r.into_json()?;
                v["delay"]
                    .as_u64()
                    .map(|d| d as u32)
                    .ok_or_else(|| anyhow!("no delay in response: {v}"))
            }
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                Err(anyhow!("delay test failed (http {code}): {body}"))
            }
            Err(e) => Err(anyhow!("clash api unreachable: {e}")),
        }
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
