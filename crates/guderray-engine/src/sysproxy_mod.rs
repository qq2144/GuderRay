//! System proxy toggle + Windows elevation helpers.

use anyhow::{Context, Result};
use serde_json::{json, Value};

/// Set the OS system proxy to point at our local mixed inbound.
pub fn set_system_proxy(host: &str, port: u16) -> Result<Value> {
    let sp = sysproxy::Sysproxy {
        enable: true,
        host: host.to_string(),
        port,
        bypass: default_bypass(),
    };
    sp.set_system_proxy().context("set system proxy")?;
    Ok(json!({ "system_proxy": "on", "host": host, "port": port, "bypass": default_bypass() }))
}

/// Disable the OS system proxy.
pub fn clear_system_proxy() -> Result<Value> {
    let mut sp = sysproxy::Sysproxy::get_system_proxy().unwrap_or(sysproxy::Sysproxy {
        enable: false,
        host: "127.0.0.1".into(),
        port: 0,
        bypass: default_bypass(),
    });
    sp.enable = false;
    sp.set_system_proxy().context("clear system proxy")?;
    Ok(json!({ "system_proxy": "off" }))
}

pub fn system_proxy_status() -> Value {
    match sysproxy::Sysproxy::get_system_proxy() {
        Ok(sp) => json!({ "enabled": sp.enable, "host": sp.host, "port": sp.port, "bypass": sp.bypass }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}

fn default_bypass() -> String {
    if cfg!(windows) {
        "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>".into()
    } else {
        "localhost,127.0.0.1,::1".into()
    }
}

/// Whether the current process runs elevated (admin/root).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        // Use the token elevation check.
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(windows))]
    {
        // uid 0 == root
        std::env::var("USER").map(|u| u == "root").unwrap_or(false)
    }
}

/// Relaunch the current executable elevated (Windows UAC) via PowerShell Start-Process.
/// Returns Ok(()) if the UAC launch was requested (caller should exit).
#[cfg(windows)]
pub fn relaunch_elevated(args: &[String]) -> Result<()> {
    let exe = std::env::current_exe().context("current_exe")?;
    let exe_str = exe.to_string_lossy().replace('\'', "''");
    // Build a PowerShell single-quoted argument list.
    let arg_list = args
        .iter()
        .map(|a| format!("'{}'", a.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let ps = if arg_list.is_empty() {
        format!("Start-Process -FilePath '{exe_str}' -Verb RunAs")
    } else {
        format!("Start-Process -FilePath '{exe_str}' -Verb RunAs -ArgumentList {arg_list}")
    };
    use std::os::windows::process::CommandExt;
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW: only the UAC dialog should appear
        .status()
        .context("launch powershell for elevation")?;
    if !status.success() {
        anyhow::bail!("elevation relaunch failed (UAC declined?)");
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn relaunch_elevated(_args: &[String]) -> Result<()> {
    anyhow::bail!("elevation relaunch is only implemented on Windows")
}
