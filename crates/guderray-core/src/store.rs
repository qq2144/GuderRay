//! On-disk persistence: config paths, profiles, settings, runtime state.

use crate::config::GenOptions;
use crate::error::{CoreError, Result};
use crate::model::Profile;
use crate::routing::{RoutingMode, UserRules};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Resolves the config root, in priority order:
/// 1. env `GUDERRAY_HOME` (explicit override, e.g. for tests)
/// 2. **portable mode**: a `data/` directory (or empty `portable` marker file) next to
///    the running executable — lets a packaged zip be "extract and run", like nekoray.
/// 3. the OS per-user config directory (`%APPDATA%\GuderRay\GuderRay` on Windows).
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn discover() -> Self {
        let root = if let Ok(h) = std::env::var("GUDERRAY_HOME") {
            PathBuf::from(h)
        } else if let Some(p) = portable_data_dir() {
            p
        } else if let Some(pd) = directories::ProjectDirs::from("", "GuderRay", "GuderRay") {
            pd.config_dir().to_path_buf()
        } else {
            PathBuf::from("config")
        };
        Paths { root }
    }

    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.assets_dir())?;
        std::fs::create_dir_all(self.logs_dir())?;
        Ok(())
    }

    pub fn profiles_file(&self) -> PathBuf {
        self.root.join("profiles.json")
    }
    pub fn settings_file(&self) -> PathBuf {
        self.root.join("settings.json")
    }
    pub fn state_file(&self) -> PathBuf {
        self.root.join("state.json")
    }
    pub fn assets_dir(&self) -> PathBuf {
        self.root.join("assets")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }
    pub fn gen_config_file(&self) -> PathBuf {
        self.root.join("gen-config.json")
    }
    pub fn subs_file(&self) -> PathBuf {
        self.root.join("subscriptions.json")
    }
    pub fn cache_file(&self) -> PathBuf {
        self.root.join("cache.db")
    }
    pub fn singbox_exe(&self) -> PathBuf {
        let name = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };
        self.assets_dir().join(name)
    }
}

/// If a `data/` dir or `portable` marker file sits next to the executable, use `<exe_dir>/data`.
fn portable_data_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    if dir.join("data").is_dir() || dir.join("portable").exists() {
        Some(dir.join("data"))
    } else {
        None
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("json")
    ));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path).or_else(|e| {
        if path.exists() {
            std::fs::remove_file(path)?;
            std::fs::rename(&tmp, path)
        } else {
            Err(e)
        }
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileStore {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_next_id")]
    pub next_id: u32,
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

fn default_next_id() -> u32 {
    1
}

/// Current on-disk config schema version. Bump when a field changes meaning/shape,
/// then add the transform in the relevant `migrate()` below.
pub const CURRENT_SCHEMA: u32 = 1;

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA
}

/// Apply version-to-version transforms in order. Returns true if anything changed.
/// (v1 is the baseline; future versions add `if from < N { ...; from = N; }` arms.)
fn run_migrations(from: &mut u32) -> bool {
    let start = *from;
    // e.g. if *from < 2 { /* rename field X */ *from = 2; }
    *from = CURRENT_SCHEMA;
    *from != start
}

impl Default for ProfileStore {
    fn default() -> Self {
        ProfileStore { schema_version: default_schema_version(), next_id: 1, profiles: Vec::new() }
    }
}

impl ProfileStore {
    pub fn load(paths: &Paths) -> Result<Self> {
        let mut s: Self = read_json(&paths.profiles_file())?.unwrap_or_default();
        if run_migrations(&mut s.schema_version) {
            let _ = s.save(paths);
        }
        Ok(s)
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        write_json(&paths.profiles_file(), self)
    }

    pub fn add(&mut self, name: String, group: Option<String>, outbound: crate::model::Outbound) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.profiles.push(Profile { id, name, group, outbound, latency: None, last_test: None });
        id
    }

    pub fn get(&self, id: u32) -> Result<&Profile> {
        self.profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or(CoreError::ProfileNotFound(id))
    }

    pub fn get_mut(&mut self, id: u32) -> Result<&mut Profile> {
        self.profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(CoreError::ProfileNotFound(id))
    }

    pub fn rename(&mut self, id: u32, name: String) -> Result<()> {
        self.get_mut(id)?.name = name;
        Ok(())
    }

    pub fn set_group(&mut self, id: u32, group: Option<String>) -> Result<()> {
        self.get_mut(id)?.group = group;
        Ok(())
    }

    pub fn replace_outbound(&mut self, id: u32, outbound: crate::model::Outbound) -> Result<()> {
        self.get_mut(id)?.outbound = outbound;
        Ok(())
    }

    pub fn set_latency(&mut self, id: u32, latency: Option<i32>, last_test: Option<i64>) -> Result<()> {
        let p = self.get_mut(id)?;
        p.latency = latency;
        p.last_test = last_test;
        Ok(())
    }

    pub fn remove(&mut self, id: u32) -> Result<()> {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        if self.profiles.len() == before {
            return Err(CoreError::ProfileNotFound(id));
        }
        Ok(())
    }

    /// Remove every profile in a group; returns how many were removed.
    pub fn remove_group(&mut self, group: &str) -> usize {
        let before = self.profiles.len();
        self.profiles
            .retain(|p| p.group.as_deref() != Some(group));
        before - self.profiles.len()
    }
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubStore {
    #[serde(default)]
    pub subs: Vec<Subscription>,
}

impl SubStore {
    pub fn load(paths: &Paths) -> Result<Self> {
        Ok(read_json(&paths.subs_file())?.unwrap_or_default())
    }
    pub fn save(&self, paths: &Paths) -> Result<()> {
        write_json(&paths.subs_file(), self)
    }
    pub fn get(&self, name: &str) -> Option<&Subscription> {
        self.subs.iter().find(|s| s.name == name)
    }
    /// Insert or update by name.
    pub fn upsert(&mut self, name: String, url: String) {
        match self.subs.iter_mut().find(|s| s.name == name) {
            Some(s) => s.url = url,
            None => self.subs.push(Subscription { name, url }),
        }
    }
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.subs.len();
        self.subs.retain(|s| s.name != name);
        self.subs.len() != before
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub routing: RoutingMode,
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
    pub user_rules: UserRules,
    pub singbox_path: Option<String>,
    /// Set the OS system proxy on `up` (and clear on `down`).
    pub system_proxy: bool,
    /// GUI theme preference, persisted across launches.
    pub ui_dark_mode: bool,
    /// Last profile the user selected in the GUI (restored on next launch).
    pub last_profile_id: Option<u32>,
    /// Auto-connect the last profile when the GUI launches.
    pub auto_connect: bool,
    /// Restart automatically if the managed sing-box process dies while GUI is running.
    pub auto_restart: bool,
    /// UI language: zh or en.
    pub language: String,
}

impl Default for Settings {
    fn default() -> Self {
        let g = GenOptions::default();
        Settings {
            schema_version: default_schema_version(),
            routing: g.routing,
            tun: g.tun,
            tun_stack: g.tun_stack,
            tun_mtu: g.tun_mtu,
            tun_strict_route: g.tun_strict_route,
            socks_port: g.socks_port,
            socks_listen: g.socks_listen,
            clash_api_port: g.clash_api_port,
            clash_api_secret: g.clash_api_secret,
            direct_dns: g.direct_dns,
            remote_dns: g.remote_dns,
            dns_strategy: g.dns_strategy,
            log_level: g.log_level,
            block_ads: g.block_ads,
            user_rules: UserRules::default(),
            singbox_path: None,
            system_proxy: false,
            ui_dark_mode: true,
            last_profile_id: None,
            auto_connect: false,
            auto_restart: false,
            language: "zh".into(),
        }
    }
}

impl Settings {
    pub fn load(paths: &Paths) -> Result<Self> {
        let mut s: Self = read_json(&paths.settings_file())?.unwrap_or_default();
        if run_migrations(&mut s.schema_version) {
            let _ = s.save(paths);
        }
        Ok(s)
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        write_json(&paths.settings_file(), self)
    }

    /// Build config-generation options. `cache_path` persists remote rule-sets.
    pub fn to_gen_options_with_paths(&self, paths: &Paths) -> GenOptions {
        let mut opt = self.to_gen_options(Some(
            paths.cache_file().to_string_lossy().replace('\\', "/"),
        ));
        opt.local_ruleset_dir = Some(paths.assets_dir().to_string_lossy().into_owned());
        opt
    }

    /// Build config-generation options. `cache_path` persists remote rule-sets.
    pub fn to_gen_options(&self, cache_path: Option<String>) -> GenOptions {
        GenOptions {
            routing: self.routing,
            user_rules: self.user_rules.clone(),
            tun: self.tun,
            tun_stack: self.tun_stack.clone(),
            tun_mtu: self.tun_mtu,
            tun_strict_route: self.tun_strict_route,
            socks_port: self.socks_port,
            socks_listen: self.socks_listen.clone(),
            clash_api_port: self.clash_api_port,
            clash_api_secret: self.clash_api_secret.clone(),
            direct_dns: self.direct_dns.clone(),
            remote_dns: self.remote_dns.clone(),
            dns_strategy: self.dns_strategy.clone(),
            log_level: self.log_level.clone(),
            block_ads: self.block_ads,
            cache_path,
            ..GenOptions::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub running: Option<Running>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Running {
    pub pid: u32,
    pub profile_id: u32,
    pub profile_name: String,
    pub clash_port: u16,
    pub clash_secret: String,
    pub socks_port: u16,
    pub tun: bool,
    #[serde(default)]
    pub system_proxy: bool,
    /// Process creation timestamp in 100ns Windows FILETIME ticks when available.
    #[serde(default)]
    pub started_at: Option<u64>,
}

impl State {
    pub fn load(paths: &Paths) -> Result<Self> {
        let mut s: Self = read_json(&paths.state_file())?.unwrap_or_default();
        if run_migrations(&mut s.schema_version) {
            let _ = s.save(paths);
        }
        Ok(s)
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        write_json(&paths.state_file(), self)
    }
}
