//! Asset management: download sing-box core and wintun.dll into the assets dir.

use anyhow::{anyhow, bail, Context, Result};
use guderray_core::Paths;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;

const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";
const WINTUN_DLL_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

fn agent() -> ureq::Agent {
    let mut b = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(600))
        .user_agent("GuderRay/0.1");
    // honor HTTPS_PROXY / HTTP_PROXY if set
    for var in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(p) = std::env::var(var) {
            if let Ok(proxy) = ureq::Proxy::new(&p) {
                b = b.proxy(proxy);
                break;
            }
        }
    }
    b.build()
}


fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn verify_sha256(bytes: &[u8], expected: &str, label: &str) -> Result<()> {
    let expected = expected.trim().trim_start_matches("sha256:").to_ascii_lowercase();
    let actual = sha256_hex(bytes);
    if actual != expected {
        bail!("{label} sha256 mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn github_asset_digest(agent: &ureq::Agent, version: &str, asset_name: &str) -> Result<Option<String>> {
    let v: Value = agent
        .get(&format!("https://api.github.com/repos/SagerNet/sing-box/releases/tags/v{version}"))
        .call()
        .with_context(|| format!("query sing-box release v{version}"))?
        .into_json()?;
    Ok(v["assets"]
        .as_array()
        .and_then(|assets| assets.iter().find(|a| a["name"].as_str() == Some(asset_name)))
        .and_then(|a| a["digest"].as_str())
        .map(|s| s.to_string()))
}
fn download(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>> {
    let resp = agent
        .get(url)
        .call()
        .with_context(|| format!("download {url}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(512 * 1024 * 1024)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

fn latest_singbox_version(agent: &ureq::Agent) -> Result<String> {
    let v: Value = agent
        .get("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
        .call()
        .context("query latest sing-box release")?
        .into_json()?;
    v["tag_name"]
        .as_str()
        .map(|t| t.trim_start_matches('v').to_string())
        .ok_or_else(|| anyhow!("no tag_name in GitHub response"))
}

fn extract_from_zip(zip_bytes: &[u8], suffix: &str) -> Result<Vec<u8>> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open zip")?;
    for i in 0..archive.len() {
        let mut f = archive.by_index(i)?;
        let name = f.name().replace('\\', "/");
        if name.ends_with(suffix) {
            let mut out = Vec::new();
            f.read_to_end(&mut out)?;
            return Ok(out);
        }
    }
    bail!("'{suffix}' not found in zip")
}

fn platform_triple() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
    (os, arch)
}

/// Download sing-box (and wintun.dll on Windows) into `paths.assets_dir()`.
pub fn sync(paths: &Paths, version: Option<&str>) -> Result<Value> {
    paths.ensure()?;
    let agent = agent();
    let mut report = json!({});

    // sing-box
    let ver = match version {
        Some(v) => v.trim_start_matches('v').to_string(),
        None => latest_singbox_version(&agent)?,
    };
    let (os, arch) = platform_triple();
    let asset_name = format!("sing-box-{ver}-{os}-{arch}.zip");
    let url = format!(
        "https://github.com/SagerNet/sing-box/releases/download/v{ver}/{asset_name}"
    );
    let exe_name = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };
    let zip_bytes = download(&agent, &url)?;
    if let Some(digest) = github_asset_digest(&agent, &ver, &asset_name)? {
        verify_sha256(&zip_bytes, &digest, "sing-box archive")?;
    } else {
        eprintln!("[warn] GitHub release asset digest missing for {asset_name}; downloaded archive was not verified");
    }
    let exe = extract_from_zip(&zip_bytes, exe_name)?;
    let exe_path = paths.singbox_exe();
    std::fs::write(&exe_path, exe).with_context(|| format!("write {}", exe_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe_path, std::fs::Permissions::from_mode(0o755))?;
    }
    report["sing_box"] = json!({ "version": ver, "path": exe_path.to_string_lossy() });

    // wintun (Windows only)
    if cfg!(windows) {
        let arch_dir = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
        let wintun_zip = download(&agent, WINTUN_URL)?;
        let dll = extract_from_zip(&wintun_zip, &format!("bin/{arch_dir}/wintun.dll"))?;
        verify_sha256(&dll, WINTUN_DLL_SHA256, "wintun.dll")?;
        let dll_path = paths.assets_dir().join("wintun.dll");
        std::fs::write(&dll_path, dll)?;
        report["wintun"] = json!({ "path": dll_path.to_string_lossy() });
    }

    // common rule-sets, cached locally so routing works before the proxy is up
    let mut rulesets = Vec::new();
    for (repo, branch, tag) in [
        ("sing-geosite", "rule-set", "geosite-cn"),
        ("sing-geosite", "rule-set", "geosite-geolocation-cn"),
        ("sing-geosite", "rule-set", "geosite-category-ads-all"),
        ("sing-geoip", "rule-set", "geoip-cn"),
    ] {
        let url =
            format!("https://raw.githubusercontent.com/SagerNet/{repo}/{branch}/{tag}.srs");
        match download(&agent, &url) {
            Ok(bytes) => {
                let p = paths.assets_dir().join(format!("{tag}.srs"));
                std::fs::write(&p, bytes)?;
                rulesets.push(json!({ "tag": tag, "ok": true }));
            }
            Err(e) => rulesets.push(json!({ "tag": tag, "ok": false, "error": e.to_string() })),
        }
    }
    report["rule_sets"] = json!(rulesets);

    Ok(report)
}
