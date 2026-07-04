//! GuderRay CLI — JSON-first control surface for agents.
//! Every invocation prints exactly one JSON envelope: {"ok":bool,"error":...,"data":...}.

use clap::{Parser, Subcommand};
use guderray_core::config::build_config;
use guderray_core::routing::RoutingMode;
use guderray_core::{link, sub, Paths, ProfileStore, Settings, SubStore};
use std::io::BufRead;
use serde_json::{json, Value};

#[derive(Parser)]
#[command(name = "guderray", version, about = "GuderRay — sing-box manager (CLI)")]
struct Cli {
    /// Pretty-print the JSON envelope (default is compact).
    #[arg(long, global = true)]
    human: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage proxy profiles.
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Print the generated sing-box config for a profile.
    Config { id: u32 },
    /// Routing mode and rules.
    Routing {
        #[command(subcommand)]
        cmd: RoutingCmd,
    },
    /// Show effective settings.
    Settings,
    /// Start a profile (spawns sing-box detached; survives CLI exit).
    Up {
        id: u32,
        /// Force TUN on for this run (requires elevation).
        #[arg(long)]
        tun: bool,
        /// Force TUN off for this run.
        #[arg(long)]
        no_tun: bool,
        /// Set the OS system proxy for this run.
        #[arg(long)]
        sysproxy: bool,
        /// Do not set the OS system proxy for this run.
        #[arg(long)]
        no_sysproxy: bool,
        /// If TUN needs admin and we're not elevated, relaunch via UAC (Windows).
        #[arg(long)]
        elevate: bool,
    },
    /// Stop the running instance.
    Down,
    /// Show running status.
    Status,
    /// Traffic totals of the running instance.
    Stats,
    /// Active connections of the running instance.
    Connections,
    /// URL-test the running proxy outbound.
    Test {
        #[arg(long, default_value = "https://www.gstatic.com/generate_204")]
        url: String,
        #[arg(long, default_value_t = 5000)]
        timeout: u32,
    },
    /// TCP-ping a profile's server (no running core needed).
    Ping {
        id: u32,
        #[arg(long, default_value_t = 3000)]
        timeout: u32,
    },
    /// Manage subscriptions.
    Sub {
        #[command(subcommand)]
        cmd: SubCmd,
    },
    /// Toggle TUN mode in settings (applies on next `up`).
    Tun {
        /// on | off
        state: String,
    },
    /// Toggle the OS system proxy (applies now if running).
    Sysproxy {
        /// on | off
        state: String,
    },
    /// Toggle launch-on-boot (Windows HKCU Run key).
    Autostart {
        /// on | off | status
        state: String,
    },
    /// Repair network state after a crash/forced kill.
    Repair,
    /// Show sing-box logs.
    Logs {
        #[arg(long, default_value_t = 80)]
        tail: usize,
    },
    /// Manage bundled assets (sing-box core, wintun).
    Assets {
        #[command(subcommand)]
        cmd: AssetsCmd,
    },
}

#[derive(Subcommand)]
enum SubCmd {
    /// Add/refresh a subscription and import its nodes into a group.
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        url: String,
    },
    /// List saved subscriptions.
    List,
    /// Remove a subscription (keeps already-imported profiles).
    Remove { name: String },
    /// Re-fetch a subscription by name, or --all.
    Update {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum AssetsCmd {
    /// Download sing-box (and wintun.dll on Windows) into the assets dir.
    Sync {
        /// Pin a sing-box version (e.g. 1.13.14); default = latest release.
        #[arg(long)]
        version: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Add profile(s) from a share link, a subscription URL, or a file of links.
    Add {
        #[arg(long)]
        link: Option<String>,
        /// Subscription URL to fetch and import.
        #[arg(long)]
        url: Option<String>,
        /// Path to a file containing one or more share links (or a base64 subscription).
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        group: Option<String>,
    },
    /// List all profiles.
    List,
    /// Show one profile.
    Show { id: u32 },
    /// Remove a profile.
    Remove { id: u32 },
    /// Rename a profile.
    Rename { id: u32, name: String },
    /// Replace a profile outbound from a share link.
    Edit {
        id: u32,
        #[arg(long)]
        link: String,
    },
    /// Set or clear a profile group (- clears).
    SetGroup { id: u32, group: String },
}

#[derive(Subcommand)]
enum RoutingCmd {
    /// Show routing mode + user rules.
    Show,
    /// Set routing mode: global | cn-direct | custom.
    Set { mode: String },
    /// Manage user rules.
    Rule {
        #[command(subcommand)]
        cmd: RuleCmd,
    },
}

#[derive(Subcommand)]
enum RuleCmd {
    /// Add a rule entry to a decision bucket.
    Add {
        #[arg(long)]
        direct: bool,
        #[arg(long)]
        proxy: bool,
        #[arg(long)]
        block: bool,
        #[arg(long)]
        domain: Vec<String>,
        #[arg(long)]
        ip: Vec<String>,
        #[arg(long)]
        process: Vec<String>,
    },
    /// Remove a rule entry from a decision bucket (exact string match).
    Remove {
        #[arg(long)]
        direct: bool,
        #[arg(long)]
        proxy: bool,
        #[arg(long)]
        block: bool,
        #[arg(long)]
        domain: Vec<String>,
        #[arg(long)]
        ip: Vec<String>,
        #[arg(long)]
        process: Vec<String>,
    },
    /// Remove every entry from a decision bucket.
    Clear {
        #[arg(long)]
        direct: bool,
        #[arg(long)]
        proxy: bool,
        #[arg(long)]
        block: bool,
    },
    /// List user rules.
    List,
}

fn profile_summary(p: &guderray_core::Profile) -> Value {
    let (server, port) = p.server_endpoint();
    json!({
        "id": p.id,
        "name": p.name,
        "group": p.group,
        "server": server,
        "port": port,
    })
}

fn run(cli: &Cli) -> anyhow::Result<Value> {
    let paths = Paths::discover();
    paths.ensure()?;

    match &cli.command {
        Command::Profile { cmd } => run_profile(&paths, cmd),
        Command::Config { id } => {
            let store = ProfileStore::load(&paths)?;
            let settings = Settings::load(&paths)?;
            let profile = store.get(*id)?;
            let opt = settings.to_gen_options_with_paths(&paths);
            Ok(build_config(profile, &opt))
        }
        Command::Routing { cmd } => run_routing(&paths, cmd),
        Command::Settings => {
            let settings = Settings::load(&paths)?;
            Ok(serde_json::to_value(settings)?)
        }
        Command::Up { id, tun, no_tun, sysproxy, no_sysproxy, elevate } => {
            let tun_override = match (tun, no_tun) {
                (true, false) => Some(true),
                (false, true) => Some(false),
                (false, false) => None,
                (true, true) => anyhow::bail!("--tun and --no-tun are mutually exclusive"),
            };
            let sysproxy_override = match (sysproxy, no_sysproxy) {
                (true, false) => Some(true),
                (false, true) => Some(false),
                (false, false) => None,
                (true, true) => anyhow::bail!("--sysproxy and --no-sysproxy are mutually exclusive"),
            };
            // If TUN is requested, we're not elevated, and --elevate was passed: relaunch via UAC.
            let want_tun = tun_override.unwrap_or_else(|| {
                Settings::load(&paths).map(|s| s.tun).unwrap_or(false)
            });
            if *elevate && want_tun && !guderray_engine::sysproxy_mod::is_elevated() {
                let mut fwd: Vec<String> = std::env::args().skip(1).collect();
                fwd.retain(|a| a != "--elevate");
                guderray_engine::sysproxy_mod::relaunch_elevated(&fwd)?;
                return Ok(json!({ "elevated_relaunch": true, "note": "started elevated process via UAC; check `status`" }));
            }
            guderray_engine::up(&paths, *id, tun_override, sysproxy_override)
        }
        Command::Down => guderray_engine::down(&paths),
        Command::Status => guderray_engine::status(&paths),
        Command::Stats => guderray_engine::stats(&paths),
        Command::Connections => guderray_engine::connections(&paths),
        Command::Test { url, timeout } => guderray_engine::test_running(&paths, url, *timeout),
        Command::Ping { id, timeout } => guderray_engine::ping_profile(&paths, *id, *timeout),
        Command::Sub { cmd } => run_sub(&paths, cmd),
        Command::Tun { state } => {
            let mut settings = Settings::load(&paths)?;
            settings.tun = match state.as_str() {
                "on" => true,
                "off" => false,
                other => anyhow::bail!("use `tun on` or `tun off`, got: {other}"),
            };
            settings.save(&paths)?;
            Ok(json!({ "tun": settings.tun, "note": "applies on next `up` (or rerun `up <id>`)" }))
        }
        Command::Sysproxy { state } => {
            let on = match state.as_str() {
                "on" => true,
                "off" => false,
                other => anyhow::bail!("use `sysproxy on` or `sysproxy off`, got: {other}"),
            };
            guderray_engine::set_sysproxy(&paths, on)
        }
        Command::Autostart { state } => match state.as_str() {
            "on" => guderray_engine::set_autostart(true),
            "off" => guderray_engine::set_autostart(false),
            "status" => Ok(json!({ "autostart": guderray_engine::get_autostart() })),
            other => anyhow::bail!("use `autostart on|off|status`, got: {other}"),
        },
        Command::Repair => guderray_engine::repair_network(&paths),
        Command::Logs { tail } => read_logs(&paths, *tail),
        Command::Assets { cmd } => match cmd {
            AssetsCmd::Sync { version } => guderray_engine::assets::sync(&paths, version.as_deref()),
        },
    }
}

fn run_profile(paths: &Paths, cmd: &ProfileCmd) -> anyhow::Result<Value> {
    let mut store = ProfileStore::load(paths)?;
    match cmd {
        ProfileCmd::Add { link: link_arg, url, file, name, group } => {
            if let Some(u) = url {
                // subscription URL import is handled by the engine (needs HTTP)
                return guderray_engine::profile_add_url(paths, u, group.as_deref());
            }
            let mut added = Vec::new();
            if let Some(l) = link_arg {
                let (parsed_name, ob) = link::parse_link(l)?;
                let nm = name.clone().unwrap_or(parsed_name);
                let id = store.add(if nm.is_empty() { "unnamed".into() } else { nm }, group.clone(), ob);
                added.push(id);
            }
            if let Some(f) = file {
                let body = std::fs::read_to_string(f)?;
                let report = sub::parse_subscription_report(&body);
                for (parsed_name, ob) in report.nodes {
                    let nm = if parsed_name.is_empty() { "unnamed".into() } else { parsed_name };
                    let id = store.add(nm, group.clone(), ob);
                    added.push(id);
                }
            }
            if added.is_empty() {
                anyhow::bail!("nothing added; provide --link, --url, or --file");
            }
            store.save(paths)?;
            Ok(json!({ "added": added, "count": added.len() }))
        }
        ProfileCmd::List => {
            let list: Vec<Value> = store.profiles.iter().map(profile_summary).collect();
            Ok(json!({ "profiles": list, "count": list.len() }))
        }
        ProfileCmd::Show { id } => {
            let p = store.get(*id)?;
            Ok(serde_json::to_value(p)?)
        }
        ProfileCmd::Remove { id } => {
            store.remove(*id)?;
            store.save(paths)?;
            Ok(json!({ "removed": id }))
        }
        ProfileCmd::Rename { id, name } => {
            store.rename(*id, name.clone())?;
            store.save(paths)?;
            Ok(json!({ "id": id, "name": name }))
        }
        ProfileCmd::Edit { id, link } => {
            let (_name, ob) = link::parse_link(link)?;
            store.replace_outbound(*id, ob)?;
            store.save(paths)?;
            Ok(json!({ "id": id, "edited": true }))
        }
        ProfileCmd::SetGroup { id, group } => {
            let group = if group == "-" || group.is_empty() { None } else { Some(group.clone()) };
            store.set_group(*id, group.clone())?;
            store.save(paths)?;
            Ok(json!({ "id": id, "group": group }))
        }
    }
}

fn run_routing(paths: &Paths, cmd: &RoutingCmd) -> anyhow::Result<Value> {
    let mut settings = Settings::load(paths)?;
    match cmd {
        RoutingCmd::Show => Ok(json!({
            "mode": settings.routing,
            "rules": settings.user_rules,
        })),
        RoutingCmd::Set { mode } => {
            settings.routing = match mode.as_str() {
                "global" => RoutingMode::Global,
                "cn-direct" | "cn" => RoutingMode::CnDirect,
                "custom" => RoutingMode::Custom,
                other => anyhow::bail!("unknown routing mode: {other} (use global|cn-direct|custom)"),
            };
            settings.save(paths)?;
            Ok(json!({ "mode": settings.routing }))
        }
        RoutingCmd::Rule { cmd } => match cmd {
            RuleCmd::List => Ok(serde_json::to_value(&settings.user_rules)?),
            RuleCmd::Add { direct, proxy, block, domain, ip, process } => {
                let bucket = pick_bucket(&mut settings.user_rules, *direct, *proxy, *block)?;
                if domain.is_empty() && ip.is_empty() && process.is_empty() {
                    anyhow::bail!("provide at least one --domain / --ip / --process");
                }
                bucket.domains.extend(domain.iter().cloned());
                bucket.ips.extend(ip.iter().cloned());
                bucket.processes.extend(process.iter().cloned());
                settings.save(paths)?;
                Ok(serde_json::to_value(&settings.user_rules)?)
            }
            RuleCmd::Remove { direct, proxy, block, domain, ip, process } => {
                let bucket = pick_bucket(&mut settings.user_rules, *direct, *proxy, *block)?;
                if domain.is_empty() && ip.is_empty() && process.is_empty() {
                    anyhow::bail!("provide at least one --domain / --ip / --process to remove");
                }
                let before = (bucket.domains.len(), bucket.ips.len(), bucket.processes.len());
                bucket.domains.retain(|d| !domain.contains(d));
                bucket.ips.retain(|i| !ip.contains(i));
                bucket.processes.retain(|p| !process.contains(p));
                let removed = (before.0 - bucket.domains.len())
                    + (before.1 - bucket.ips.len())
                    + (before.2 - bucket.processes.len());
                settings.save(paths)?;
                Ok(json!({ "removed_count": removed, "rules": settings.user_rules }))
            }
            RuleCmd::Clear { direct, proxy, block } => {
                let bucket = pick_bucket(&mut settings.user_rules, *direct, *proxy, *block)?;
                *bucket = guderray_core::RuleList::default();
                settings.save(paths)?;
                Ok(serde_json::to_value(&settings.user_rules)?)
            }
        },
    }
}

fn pick_bucket(
    rules: &mut guderray_core::UserRules,
    direct: bool,
    proxy: bool,
    block: bool,
) -> anyhow::Result<&mut guderray_core::RuleList> {
    match (direct, proxy, block) {
        (true, false, false) => Ok(&mut rules.direct),
        (false, true, false) => Ok(&mut rules.proxy),
        (false, false, true) => Ok(&mut rules.block),
        _ => anyhow::bail!("specify exactly one of --direct | --proxy | --block"),
    }
}

fn run_sub(paths: &Paths, cmd: &SubCmd) -> anyhow::Result<Value> {
    match cmd {
        SubCmd::Add { name, url } => guderray_engine::sub_add(paths, name, url),
        SubCmd::List => {
            let subs = SubStore::load(paths)?;
            Ok(json!({ "subscriptions": subs.subs, "count": subs.subs.len() }))
        }
        SubCmd::Remove { name } => {
            let mut subs = SubStore::load(paths)?;
            let removed = subs.remove(name);
            subs.save(paths)?;
            Ok(json!({ "removed": removed, "name": name }))
        }
        SubCmd::Update { name, all } => {
            if !*all && name.is_none() {
                anyhow::bail!("specify --name <n> or --all");
            }
            guderray_engine::sub_update(paths, if *all { None } else { name.as_deref() })
        }
    }
}


fn read_logs(paths: &Paths, tail: usize) -> anyhow::Result<Value> {
    let path = paths.logs_dir().join("sing-box.log");
    let file = std::fs::File::open(&path)?;
    let reader = std::io::BufReader::new(file);
    let mut lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;
    if lines.len() > tail {
        lines = lines.split_off(lines.len() - tail);
    }
    Ok(json!({ "path": path.to_string_lossy(), "lines": lines }))
}
fn main() {
    let cli = Cli::parse();
    let (envelope, code) = match run(&cli) {
        Ok(data) => (json!({ "ok": true, "error": Value::Null, "data": data }), 0),
        Err(e) => {
            let code = e
                .downcast_ref::<guderray_engine::Coded>()
                .map(|c| c.code)
                .unwrap_or(1);
            (json!({ "ok": false, "error": e.to_string(), "data": Value::Null }), code)
        }
    };
    let out = if cli.human {
        serde_json::to_string_pretty(&envelope).unwrap()
    } else {
        serde_json::to_string(&envelope).unwrap()
    };
    println!("{out}");
    std::process::exit(code);
}
