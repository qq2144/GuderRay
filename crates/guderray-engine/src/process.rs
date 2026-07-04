//! Detached sing-box process management.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::{Command, Stdio};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// Spawn `sing-box run -c <config>` detached, stdout+stderr to `log_path`.
/// Returns the pid. The child outlives this process.
pub fn spawn_singbox(exe: &Path, config: &Path, workdir: &Path, log_path: &Path) -> Result<u32> {
    let log = std::fs::File::create(log_path)
        .with_context(|| format!("create log file {}", log_path.display()))?;
    let log_err = log.try_clone()?;

    let mut cmd = Command::new(exe);
    cmd.arg("run")
        .arg("-c")
        .arg(config)
        .current_dir(workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", exe.display()))?;
    Ok(child.id())
}

/// Best-effort check whether a pid is alive.
/// On Windows this uses the process API directly — no `tasklist` subprocess. The GUI
/// polls this every 1.5s, and a spawned console subprocess would flash a window each time.
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let mut code: u32 = 0;
            let ok = GetExitCodeProcess(h, &mut code);
            CloseHandle(h);
            ok != 0 && code == STILL_ACTIVE as u32
        }
    }
    #[cfg(not(windows))]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Terminate the process tree.
pub fn kill(pid: u32) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let out = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .context("run taskkill")?;
        if !out.status.success() && pid_alive(pid) {
            bail!(
                "taskkill failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let ok = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok && pid_alive(pid) {
            bail!("kill failed for pid {pid}");
        }
        Ok(())
    }
}

/// Read the last `n` lines of a log file (for error reporting).
pub fn log_tail(log_path: &Path, n: usize) -> String {
    match std::fs::read_to_string(log_path) {
        Ok(s) => {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(n);
            lines[start..].join("\n")
        }
        Err(_) => String::new(),
    }
}

/// Process creation timestamp. On Windows this is FILETIME 100ns ticks since 1601.
pub fn process_started_at(pid: u32) -> Option<u64> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut create = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let mut exit = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let mut kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let mut user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let ok = GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user);
            CloseHandle(h);
            if ok == 0 {
                None
            } else {
                Some(((create.dwHighDateTime as u64) << 32) | create.dwLowDateTime as u64)
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        None
    }
}

/// Alive check plus creation-time comparison when the platform can provide it.
pub fn pid_matches(pid: u32, started_at: Option<u64>) -> bool {
    if !pid_alive(pid) {
        return false;
    }
    match (started_at, process_started_at(pid)) {
        (Some(expected), Some(actual)) => expected == actual,
        _ => true,
    }
}