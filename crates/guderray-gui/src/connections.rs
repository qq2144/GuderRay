//! Maps the JSON returned by `guderray_engine::connections()` into a typed row list.
//! Shared by the Dashboard preview (Phase 3) and the full Connections view (Phase 5) so
//! there's exactly one place that knows the engine's connection JSON shape.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct ConnRow {
    pub id: String,
    pub host: String,
    pub destination: String,
    pub network: String,
    pub rule: String,
    pub chains: Vec<String>,
    pub download: u64,
    pub upload: u64,
    pub start: String,
}

/// `v` is the top-level value returned by `guderray_engine::connections()`,
/// i.e. `{"count": N, "connections": [...]}`.
pub fn map_connections(v: &Value) -> Vec<ConnRow> {
    v["connections"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|c| ConnRow {
            id: c["id"].as_str().unwrap_or("").to_string(),
            host: c["host"].as_str().unwrap_or("").to_string(),
            destination: c["destination"].as_str().unwrap_or("").to_string(),
            network: c["network"].as_str().unwrap_or("").to_string(),
            rule: c["rule"].as_str().unwrap_or("").to_string(),
            chains: c["chains"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            download: c["download"].as_u64().unwrap_or(0),
            upload: c["upload"].as_u64().unwrap_or(0),
            start: c["start"].as_str().unwrap_or("").to_string(),
        })
        .collect()
}

/// `H:MM:SS` elapsed since an RFC3339 `start` timestamp (the Clash API's format,
/// verified against a real running node: `2026-07-03T17:26:55.2553291+08:00`).
/// Empty string if `start` is missing or unparseable, rather than panicking.
pub fn elapsed_since(start: &str) -> String {
    let Ok(started) = chrono::DateTime::parse_from_rfc3339(start) else {
        return String::new();
    };
    let now = chrono::Utc::now().with_timezone(started.offset());
    let secs = (now - started).num_seconds().max(0);
    format!("{}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_a_realistic_connections_payload() {
        let v = json!({
            "count": 2,
            "connections": [
                {
                    "id": "conn-1",
                    "host": "example.com",
                    "destination": "1.2.3.4:443",
                    "network": "tcp",
                    "rule": "match",
                    "chains": ["direct"],
                    "download": 1024,
                    "upload": 512,
                    "start": "2026-01-01T00:00:00Z"
                },
                {
                    "id": "conn-2",
                    "host": "",
                    "destination": "5.6.7.8:80",
                    "network": "udp",
                    "rule": "domain(ads.example)",
                    "chains": ["proxy", "auto"],
                    "download": 0,
                    "upload": 0,
                    "start": "2026-01-01T00:00:01Z"
                }
            ]
        });
        let rows = map_connections(&v);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            ConnRow {
                id: "conn-1".into(),
                host: "example.com".into(),
                destination: "1.2.3.4:443".into(),
                network: "tcp".into(),
                rule: "match".into(),
                chains: vec!["direct".into()],
                download: 1024,
                upload: 512,
                start: "2026-01-01T00:00:00Z".into(),
            }
        );
        assert_eq!(rows[1].host, "");
        assert_eq!(rows[1].chains, vec!["proxy".to_string(), "auto".to_string()]);
    }

    #[test]
    fn missing_fields_default_instead_of_panicking() {
        let v = json!({ "count": 1, "connections": [ {} ] });
        let rows = map_connections(&v);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host, "");
        assert_eq!(rows[0].download, 0);
        assert!(rows[0].chains.is_empty());
    }

    #[test]
    fn empty_or_missing_connections_array_yields_empty_vec() {
        assert!(map_connections(&json!({})).is_empty());
        assert!(map_connections(&json!({"connections": []})).is_empty());
    }

    #[test]
    fn elapsed_since_parses_the_real_clash_api_timestamp_format() {
        // format observed against a real running node: fractional seconds + UTC offset
        let started = chrono::Utc::now() - chrono::Duration::seconds(65);
        let start_str = started.to_rfc3339();
        let elapsed = elapsed_since(&start_str);
        assert!(elapsed == "0:01:05" || elapsed == "0:01:06", "got {elapsed}");
    }

    #[test]
    fn elapsed_since_returns_empty_for_unparseable_input() {
        assert_eq!(elapsed_since(""), "");
        assert_eq!(elapsed_since("not-a-date"), "");
    }
}
