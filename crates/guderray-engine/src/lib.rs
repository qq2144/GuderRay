//! GuderRay engine: sing-box process lifecycle, Clash API control plane, assets.

pub mod assets;
pub mod clash;
pub mod process;
pub mod sysproxy_mod;

use anyhow::{anyhow, bail, Context, Result};
use guderray_core::config::{build_config, PROXY_TAG};
use guderray_core::{Paths, ProfileStore, Running, Settings, State, SubStore};
use serde_json::{json, Value};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Error carrying a CLI exit code (3 = engine unreachable, 4 = needs elevation).
#[derive(Debug)]
pub struct Coded {
    pub code: i32,
    pub msg: String,
}

impl std::fmt::Display for Coded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}
impl std::error::Error for Coded {}

pub fn coded(code: i32, msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Coded { code, msg: msg.into() })
}

/// True if we can bind 127.0.0.1:port right now (i.e. it's free).
fn port_is_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Return `preferred` if it's free, otherwise the first free port scanning up from `base`.
fn ensure_free_port(preferred: u16, base: u16) -> u16 {
    if port_is_free(preferred) {
        return preferred;
    }
    for p in base..=base.saturating_add(400) {
        if port_is_free(p) {
            return p;
        }
    }
    preferred // give up; let sing-box surface the bind error
}

/// Resolve the sing-box executable: settings override → assets dir → PATH.
pub fn resolve_singbox(paths: &Paths, settings: &Settings) -> Result<PathBuf> {
    if let Some(p) = &settings.singbox_path {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Ok(pb);
        }
        bail!("settings.singbox_path does not exist: {p}");
    }
    let assets = paths.singbox_exe();
    if assets.exists() {
        return Ok(assets);
    }
    // PATH lookup
    let name = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let cand = dir.join(name);
            if cand.exists() {
                return Ok(cand);
            }
        }
    }
    Err(coded(
        3,
        "sing-box not found; run `guderray assets sync` first (or set settings.singbox_path)",
    ))
}

fn rotate_log(path: &std::path::Path, max_bytes: u64) {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > max_bytes => {
            let rotated = path.with_extension("log.1");
            let _ = std::fs::remove_file(&rotated);
            if let Err(e) = std::fs::rename(path, &rotated) {
                eprintln!("[warn] failed to rotate log {}: {e}", path.display());
            }
        }
        _ => {}
    }
}

/// Reconcile stale runtime state after a crash or forced kill.
pub fn reconcile(paths: &Paths) -> Result<Value> {
    let mut state = State::load(paths)?;
    let mut cleaned = false;
    if let Some(run) = &state.running {
        if !process::pid_matches(run.pid, run.started_at) {
            if run.system_proxy {
                if let Err(e) = sysproxy_mod::clear_system_proxy() {
                    eprintln!("[warn] failed to clear stale system proxy: {e}");
                }
            }
            state.running = None;
            state.save(paths)?;
            cleaned = true;
        }
    }
    Ok(json!({ "reconciled": true, "cleaned_stale_state": cleaned }))
}

/// Force network cleanup: clear system proxy, stop the recorded process, and kill leftover sing-box.
pub fn repair_network(paths: &Paths) -> Result<Value> {
    if let Err(e) = sysproxy_mod::clear_system_proxy() {
        eprintln!("[warn] failed to clear system proxy during repair: {e}");
    }
    let mut killed = Vec::new();
    let mut state = State::load(paths)?;
    if let Some(run) = state.running.take() {
        if process::pid_alive(run.pid) {
            if let Err(e) = process::kill(run.pid) {
                eprintln!("[warn] failed to kill recorded sing-box pid {}: {e}", run.pid);
            } else {
                killed.push(run.pid);
            }
        }
    }
    state.save(paths)?;
    kill_leftover_singbox(&mut killed);
    Ok(json!({ "system_proxy_cleared": true, "killed_pids": killed }))
}

#[cfg(windows)]
fn kill_leftover_singbox(killed: &mut Vec<u32>) {
    use std::os::windows::process::CommandExt;
    if let Ok(out) = std::process::Command::new("taskkill")
        .args(["/IM", "sing-box.exe", "/F", "/T"])
        .creation_flags(0x0800_0000)
        .output()
    {
        if out.status.success() {
            killed.push(0);
        }
    }
}

#[cfg(not(windows))]
fn kill_leftover_singbox(_killed: &mut Vec<u32>) {}
/// Start a profile. Writes gen-config.json, spawns sing-box detached,
/// waits for the Clash API, persists state. `tun_override` forces TUN on/off for this run.
pub fn up(
    paths: &Paths,
    profile_id: u32,
    tun_override: Option<bool>,
    sysproxy_override: Option<bool>,
) -> Result<Value> {
    let store = ProfileStore::load(paths)?;
    let mut settings = Settings::load(paths)?;
    let profile = store.get(profile_id)?.clone();

    if let Some(t) = tun_override {
        settings.tun = t;
    }
    if let Some(sp) = sysproxy_override {
        settings.system_proxy = sp;
    }

    // TUN needs elevation on Windows; fail early with a clear code-4 message.
    if settings.tun && !sysproxy_mod::is_elevated() {
        return Err(coded(
            4,
            "TUN mode requires administrator privileges. Run guderray from an elevated shell \
             (or use `up <id> --tun --elevate` to relaunch via UAC).",
        ));
    }

    // stop an existing instance first
    let mut state = State::load(paths)?;
    if let Some(run) = &state.running {
        if run.system_proxy {
            if let Err(e) = sysproxy_mod::clear_system_proxy() { eprintln!("[warn] failed to clear system proxy: {e}"); }
        }
        if process::pid_matches(run.pid, run.started_at) {
            process::kill(run.pid).context("stop previous instance")?;
        }
        state.running = None;
        state.save(paths)?;
    }

    let exe = resolve_singbox(paths, &settings)?;

    // Port auto-fallback: if the configured socks/clash ports are taken (e.g. another
    // proxy app like nekoray is running), pick free ones instead of failing with a
    // cryptic bind error. The chosen ports go into state so status/stats reattach.
    let socks_port = ensure_free_port(settings.socks_port, 20800);
    let clash_port = ensure_free_port(settings.clash_api_port, 29090);
    if socks_port != settings.socks_port {
        settings.socks_port = socks_port;
    }
    if clash_port != settings.clash_api_port {
        settings.clash_api_port = clash_port;
    }

    // generate + validate config
    let opt = settings.to_gen_options_with_paths(paths);
    let config = build_config(&profile, &opt);
    let config_path = paths.gen_config_file();
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;

    let mut check_cmd = std::process::Command::new(&exe);
    check_cmd.arg("check").arg("-c").arg(&config_path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        check_cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console flash from GUI
    }
    let check = check_cmd.output().context("run sing-box check")?;
    if !check.status.success() {
        bail!(
            "generated config failed sing-box check: {}",
            String::from_utf8_lossy(&check.stderr).trim()
        );
    }

    // spawn detached
    let log_path = paths.logs_dir().join("sing-box.log");
    rotate_log(&log_path, 5 * 1024 * 1024);
    let pid = process::spawn_singbox(&exe, &config_path, &paths.root, &log_path)?;

    // wait for the clash api
    let clash = clash::Clash::new(settings.clash_api_port, &settings.clash_api_secret);
    let deadline = Instant::now() + Duration::from_secs(8);
    let version = loop {
        if let Ok(v) = clash.version() {
            break v;
        }
        if !process::pid_matches(pid, process::process_started_at(pid)) {
            let tail = process::log_tail(&log_path, 25);
            let needs_admin = tail.contains("Access is denied")
                || tail.contains("administrator")
                || (settings.tun && tail.to_lowercase().contains("tun"));
            let msg = format!("sing-box exited during startup. log tail:\n{tail}");
            if settings.tun && needs_admin {
                return Err(coded(4, format!("{msg}\n\nTUN mode requires an elevated (administrator) shell.")));
            }
            bail!(msg);
        }
        if Instant::now() > deadline {
            if let Err(e) = process::kill(pid) { eprintln!("[warn] failed to kill timed-out sing-box pid {pid}: {e}"); }
            bail!(
                "clash api did not come up within 8s. log tail:\n{}",
                process::log_tail(&log_path, 25)
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    };

    // optional system proxy
    let mut sysproxy_applied = false;
    if settings.system_proxy {
        match sysproxy_mod::set_system_proxy("127.0.0.1", settings.socks_port) {
            Ok(_) => sysproxy_applied = true,
            Err(e) => eprintln!("[warn] failed to set system proxy: {e}"),
        }
    }

    // persist state
    state.running = Some(Running {
        pid,
        started_at: process::process_started_at(pid),
        profile_id: profile.id,
        profile_name: profile.name.clone(),
        clash_port: settings.clash_api_port,
        clash_secret: settings.clash_api_secret.clone(),
        socks_port: settings.socks_port,
        tun: settings.tun,
        system_proxy: sysproxy_applied,
    });
    state.save(paths)?;

    Ok(json!({
        "pid": pid,
        "profile": { "id": profile.id, "name": profile.name },
        "socks_port": settings.socks_port,
        "tun": settings.tun,
        "system_proxy": sysproxy_applied,
        "clash_api": format!("127.0.0.1:{}", settings.clash_api_port),
        "core_version": version,
        "log": log_path.to_string_lossy(),
    }))
}

/// Stop the running instance.
pub fn down(paths: &Paths) -> Result<Value> {
    let mut state = State::load(paths)?;
    match state.running.take() {
        Some(run) => {
            if run.system_proxy {
                if let Err(e) = sysproxy_mod::clear_system_proxy() { eprintln!("[warn] failed to clear system proxy: {e}"); }
            }
            let was_alive = process::pid_alive(run.pid);
            if was_alive {
                process::kill(run.pid)?;
            }
            state.save(paths)?;
            Ok(json!({ "stopped": run.pid, "was_alive": was_alive, "profile": run.profile_name, "system_proxy_cleared": run.system_proxy }))
        }
        None => Ok(json!({ "stopped": Value::Null, "message": "nothing running" })),
    }
}

/// Toggle the system proxy immediately if an instance is running, else just record intent.
pub fn set_sysproxy(paths: &Paths, on: bool) -> Result<Value> {
    let mut settings = Settings::load(paths)?;
    settings.system_proxy = on;
    settings.save(paths)?;

    let mut state = State::load(paths)?;
    if let Some(run) = &mut state.running {
        if process::pid_matches(run.pid, run.started_at) {
            let res = if on {
                sysproxy_mod::set_system_proxy("127.0.0.1", run.socks_port)?
            } else {
                sysproxy_mod::clear_system_proxy()?
            };
            run.system_proxy = on;
            state.save(paths)?;
            return Ok(res);
        }
    }
    Ok(json!({ "system_proxy": if on { "on" } else { "off" }, "applied": false, "note": "no running instance; applies on next `up`" }))
}

/// Attach to the running instance's Clash API (errors with code 3 if not running).
pub fn attach(paths: &Paths) -> Result<(Running, clash::Clash)> {
    let state = State::load(paths)?;
    let run = state
        .running
        .ok_or_else(|| coded(3, "no running instance (state empty); use `guderray up <id>`"))?;
    if !process::pid_matches(run.pid, run.started_at) {
        return Err(coded(3, format!("recorded pid {} is not alive; state is stale", run.pid)));
    }
    let clash = clash::Clash::new(run.clash_port, &run.clash_secret);
    Ok((run, clash))
}

/// Status summary (never fails; reports not-running states).
pub fn status(paths: &Paths) -> Result<Value> {
    let state = State::load(paths)?;
    match state.running {
        None => Ok(json!({ "running": false })),
        Some(run) => {
            let alive = process::pid_matches(run.pid, run.started_at);
            if !alive {
                return Ok(json!({ "running": false, "stale_state": true, "last_pid": run.pid }));
            }
            let clash = clash::Clash::new(run.clash_port, &run.clash_secret);
            let version = clash.version().ok();
            Ok(json!({
                "running": true,
                "pid": run.pid,
                "profile": { "id": run.profile_id, "name": run.profile_name },
                "socks_port": run.socks_port,
                "tun": run.tun,
                "clash_api": format!("127.0.0.1:{}", run.clash_port),
                "core_version": version,
            }))
        }
    }
}

/// Traffic totals + connection count from /connections.
pub fn stats(paths: &Paths) -> Result<Value> {
    let (_, clash) = attach(paths)?;
    let v = clash.connections()?;
    let conns = v["connections"].as_array().map(|a| a.len()).unwrap_or(0);
    Ok(json!({
        "download_total": v["downloadTotal"],
        "upload_total": v["uploadTotal"],
        "active_connections": conns,
        "memory": v["memory"],
    }))
}

/// Active connections list (host, destination, matched rule, outbound chain, traffic).
pub fn connections(paths: &Paths) -> Result<Value> {
    let (_, clash) = attach(paths)?;
    let v = clash.connections()?;
    let list: Vec<Value> = v["connections"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|c| {
            json!({
                "id": c["id"],
                "host": c["metadata"]["host"],
                "destination": format!(
                    "{}:{}",
                    c["metadata"]["destinationIP"].as_str().unwrap_or(""),
                    c["metadata"]["destinationPort"].as_str().unwrap_or("")
                ),
                "network": c["metadata"]["network"],
                "rule": c["rule"],
                "chains": c["chains"],
                "download": c["download"],
                "upload": c["upload"],
                "start": c["start"],
            })
        })
        .collect();
    Ok(json!({ "count": list.len(), "connections": list }))
}

/// Close one active connection by id (see `Clash::close_connection` for why `id` had to
/// be added to `connections()`'s output first — it was silently dropped before).
pub fn close_connection(paths: &Paths, id: &str) -> Result<Value> {
    let (_, clash) = attach(paths)?;
    clash.close_connection(id)?;
    Ok(json!({ "closed": id }))
}

/// Close every active connection.
pub fn close_all_connections(paths: &Paths) -> Result<Value> {
    let (_, clash) = attach(paths)?;
    clash.close_all_connections()?;
    Ok(json!({ "closed": "all" }))
}

// ---------------------------------------------------------------------------
// Autostart (Windows: HKCU Run key)
// ---------------------------------------------------------------------------

const AUTOSTART_NAME: &str = "GuderRay";

#[cfg(windows)]
pub fn set_autostart(enable: bool) -> Result<Value> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (run, _) = hkcu
        .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")
        .context("open Run key")?;
    if enable {
        let exe = std::env::current_exe()?;
        run.set_value(AUTOSTART_NAME, &format!("\"{}\"", exe.display()))?;
    } else {
        let _ = run.delete_value(AUTOSTART_NAME);
    }
    Ok(json!({ "autostart": enable }))
}

#[cfg(windows)]
pub fn get_autostart() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")
        .and_then(|k| k.get_value::<String, _>(AUTOSTART_NAME))
        .is_ok()
}

#[cfg(not(windows))]
pub fn set_autostart(_enable: bool) -> Result<Value> {
    bail!("autostart is only implemented on Windows")
}

#[cfg(not(windows))]
pub fn get_autostart() -> bool {
    false
}

/// URL-test the running proxy outbound.
pub fn test_running(paths: &Paths, url: &str, timeout_ms: u32) -> Result<Value> {
    let (_, clash) = attach(paths)?;
    let ms = clash
        .delay(PROXY_TAG, url, timeout_ms)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(json!({ "url": url, "delay_ms": ms }))
}

/// TCP-ping a profile's server:port (does not need a running core). Returns latency ms.
pub fn ping_profile(paths: &Paths, id: u32, timeout_ms: u32) -> Result<Value> {
    let mut store = ProfileStore::load(paths)?;
    let profile = store.get(id)?.clone();
    let (host, port) = profile.server_endpoint();
    let addr = format!("{host}:{port}");
    let socket_addrs: Vec<_> = addr
        .to_socket_addrs()
        .with_context(|| format!("resolve {addr}"))?
        .collect();
    let target = socket_addrs
        .first()
        .ok_or_else(|| anyhow!("no address resolved for {addr}"))?;
    let start = Instant::now();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    match std::net::TcpStream::connect_timeout(target, Duration::from_millis(timeout_ms as u64)) {
        Ok(_) => {
            let delay = start.elapsed().as_millis() as i32;
            store.set_latency(id, Some(delay), Some(now))?;
            store.save(paths)?;
            Ok(json!({
                "id": id,
                "server": host,
                "port": port,
                "delay_ms": delay,
                "reachable": true,
            }))
        }
        Err(e) => {
            store.set_latency(id, Some(-2), Some(now))?;
            store.save(paths)?;
            Ok(json!({
                "id": id, "server": host, "port": port,
                "reachable": false, "error": e.to_string(),
            }))
        }
    }
}
fn http_get(url: &str) -> Result<String> {
    let mut b = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .user_agent("GuderRay/0.1 (sing-box; ClashMeta compatible)");
    for var in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(p) = std::env::var(var) {
            if let Ok(proxy) = ureq::Proxy::new(&p) {
                b = b.proxy(proxy);
                break;
            }
        }
    }
    let body = b
        .build()
        .get(url)
        .call()
        .with_context(|| format!("fetch subscription {url}"))?
        .into_string()?;
    Ok(body)
}

/// Fetch a subscription URL, parse it, and (re)place its group's profiles.
fn import_sub(paths: &Paths, name: &str, url: &str) -> Result<usize> {
    let body = http_get(url)?;
    let report = guderray_core::sub::parse_subscription_report(&body);
    let parsed = report.nodes;
    let mut store = ProfileStore::load(paths)?;
    store.remove_group(name);
    for (nm, ob) in &parsed {
        let nm = if nm.is_empty() { "unnamed".into() } else { nm.clone() };
        store.add(nm, Some(name.to_string()), ob.clone());
    }
    store.save(paths)?;
    Ok(parsed.len())
}

/// Add or refresh a subscription and import its nodes into a group named `name`.
pub fn sub_add(paths: &Paths, name: &str, url: &str) -> Result<Value> {
    let mut subs = SubStore::load(paths)?;
    subs.upsert(name.to_string(), url.to_string());
    subs.save(paths)?;
    let count = import_sub(paths, name, url)?;
    Ok(json!({ "name": name, "url": url, "imported": count }))
}

/// Update one subscription by name, or all of them.
pub fn sub_update(paths: &Paths, which: Option<&str>) -> Result<Value> {
    let subs = SubStore::load(paths)?;
    let targets: Vec<_> = match which {
        Some(n) => subs
            .subs
            .iter()
            .filter(|s| s.name == n)
            .cloned()
            .collect(),
        None => subs.subs.clone(),
    };
    if targets.is_empty() {
        bail!("no matching subscription (add one with `sub add --name <n> --url <u>`)");
    }
    let mut results = Vec::new();
    for s in targets {
        match import_sub(paths, &s.name, &s.url) {
            Ok(c) => results.push(json!({ "name": s.name, "ok": true, "imported": c })),
            Err(e) => results.push(json!({ "name": s.name, "ok": false, "error": e.to_string() })),
        }
    }
    Ok(json!({ "updated": results }))
}

/// Import nodes from a subscription URL into a group without persisting the subscription.
pub fn profile_add_url(paths: &Paths, url: &str, group: Option<&str>) -> Result<Value> {
    let body = http_get(url)?;
    let report = guderray_core::sub::parse_subscription_report(&body);
    let parsed = report.nodes;
    let mut store = ProfileStore::load(paths)?;
    let mut added = Vec::new();
    for (nm, ob) in &parsed {
        let nm = if nm.is_empty() { "unnamed".into() } else { nm.clone() };
        added.push(store.add(nm, group.map(String::from), ob.clone()));
    }
    store.save(paths)?;
    Ok(json!({ "added": added, "count": added.len(), "format": report.format, "skipped": report.skipped }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_free_port_returns_preferred_when_free() {
        // bind a port, then confirm ensure_free_port avoids it
        let taken = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken_port = taken.local_addr().unwrap().port();
        let chosen = ensure_free_port(taken_port, 41000);
        assert_ne!(chosen, taken_port, "should fall back off an occupied port");
        assert!(port_is_free(chosen), "the chosen fallback port must be free");
    }

    #[test]
    fn ensure_free_port_keeps_preferred_when_available() {
        // find a currently-free port, release it, then ask for it
        let p = {
            let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            l.local_addr().unwrap().port()
        };
        assert_eq!(ensure_free_port(p, 41500), p);
    }
}
