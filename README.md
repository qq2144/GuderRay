# GuderRay

A Rust rewrite of a nekoray-style proxy manager. **The proxy engine is [sing-box]** (a prebuilt binary — never compiled here); GuderRay only *manages* it: generates config, starts/stops the process, splits traffic, manages subscriptions, and exposes everything as a JSON CLI (for agents) plus a Slint GUI.

Design goals: **国内直连 / 国外走代理** (China-direct routing under TUN), **CLI-first for AI agents**, **modern GUI**, and **no Visual Studio required**.

## Why this design

- The hard part (proxying, TUN, routing) is done by sing-box. GuderRay is a thin manager.
- Control plane = sing-box's **Clash API** (REST). No custom gRPC core.
- China-direct uses sing-box **rule_set** (`geosite-cn` / `geoip-cn`), auto-updated.
- Domain-vs-IP under TUN: sing-box **sniffs** SNI/Host and does **DNS split**, so the
  "whitelist" accepts **both domains and IPs** — GuderRay compiles each to the right layer.

## Crates

| Crate | Role |
|-------|------|
| `guderray-core` | model, share-link/subscription parsing, **sing-box config generation**, routing (unified domain/IP/process rules), persistence |
| `guderray-engine` | detached sing-box process mgmt, Clash API client, assets download, system proxy, elevation |
| `guderray-cli` → `guderray` | JSON-first CLI (agent-callable) |
| `guderray-gui` → `guderray-gui` | Slint desktop UI (thin shell over core+engine) |

## Compile

Requires only Rust (`rustup`) — no Visual Studio install needed; this repo builds fine on
the stock MSVC toolchain that ships with `rustup`. (If you'd rather avoid the MSVC linker
entirely, `rustup target add x86_64-pc-windows-gnu` and build with `--target
x86_64-pc-windows-gnu` — pure-Rust CLI/engine/core compile there too; only the Slint GUI's
GNU support is less battle-tested.)

```sh
# debug build (fast iterate, unoptimized, target/debug/)
cargo build

# release build (optimized, stripped, target/release/) — use this for anything you'll run for real
cargo build --release
```

Build only one binary if you don't need the GUI yet:

```sh
cargo build --release -p guderray-cli   # -> target/release/guderray.exe
cargo build --release -p guderray-gui   # -> target/release/guderray-gui.exe
```

## Run (from a dev checkout)

The exe looks for `sing-box.exe` first at `<config-dir>/assets/`, so fetch it once:

```sh
cargo run --release -p guderray-cli -- assets sync      # downloads sing-box + wintun.dll + rule-sets
cargo run --release -p guderray-cli -- profile add --link "vless://..."
cargo run --release -p guderray-cli -- routing set cn-direct
cargo run --release -p guderray-cli -- up 1
cargo run --release -p guderray-gui                      # or launch the GUI
```

(`cargo run -p guderray-cli --` can be swapped for the built `target\release\guderray.exe`
directly once you've compiled — that's what you'll do after packaging, below.)

By default state/config live under `%APPDATA%\GuderRay\GuderRay\` (see **Config location**
below); set `GUDERRAY_HOME=<dir>` to point at any folder instead, which is also how the
portable package (next section) becomes self-contained.

## Package (portable zip, like nekoray's release zip)

```powershell
pwsh ./scripts/package.ps1
```

This does a release build, then produces `dist\GuderRay-<version>-windows-x86_64\` (and a
matching `.zip`) containing:

```
guderray.exe
guderray-gui.exe
portable              <- empty marker file
data/
  assets/
    sing-box.exe      <- downloaded automatically during packaging
    wintun.dll
    geosite-cn.srs, geosite-geolocation-cn.srs, geosite-category-ads-all.srs, geoip-cn.srs
PORTABLE_README.txt
README.md
```

Because a `data\` folder sits next to the exe, GuderRay runs in **portable mode**: all
config/state/logs stay inside that folder — nothing touches `%APPDATA%` or the registry
(other than the system-proxy toggle, which is by design — see `sysproxy on|off`). Unzip
anywhere, including a USB drive, and `guderray.exe` / `guderray-gui.exe` just work.

Useful flags:

```powershell
pwsh ./scripts/package.ps1 -SkipBuild                    # reuse an existing target/release build
pwsh ./scripts/package.ps1 -SingBoxVersion 1.13.14        # pin a specific sing-box release
pwsh ./scripts/package.ps1 -SkipAssets                    # copy assets from $env:GUDERRAY_HOME
                                                            # instead of re-downloading (offline)
```

To hand-roll packaging (or on a non-Windows CI runner) without the script: build release,
copy the two exes plus an empty `data/` folder next to them, then run
`guderray.exe assets sync` once with `GUDERRAY_HOME` pointed at that `data/` folder — the
exe's own portable-mode detection then picks it up automatically on every future run from
that folder, no env var needed.

## Quick start (CLI)

```sh
guderray assets sync                 # download sing-box + wintun + rule-sets
guderray profile add --link "vless://…"      # or --url <subscription> / --file links.txt
guderray routing set cn-direct               # 国内直连，国外走代理
guderray up 1                                # start (mixed inbound at 127.0.0.1:<socks_port>)
guderray status                              # running state
guderray up 1 --tun --sysproxy --elevate     # TUN + system proxy (UAC elevates for TUN)
guderray down                                # stop
```

Custom split rules — **domains, IPs, and process names share one entry point**:

```sh
guderray routing rule add --direct --domain example.cn --process wechat.exe
guderray routing rule add --proxy  --domain chatgpt.com
guderray routing rule add --block  --domain ads.example.com
```

Every command prints one JSON envelope `{"ok":bool,"error":…,"data":…}` (add `--human` to
pretty-print). Exit codes: `0` ok, `1` error, `2` usage, `3` engine unreachable, `4` needs elevation.

## GUI

```
guderray-gui
```

A Slint (Fluent-style) desktop UI over the same core+engine as the CLI — six views behind
a left icon rail (Dashboard / Nodes / Connections / Rules / Subscriptions / Settings), all
reading/writing the same state `guderray.exe` does, so CLI and GUI stay interchangeable.

- **Dashboard** — hero status card (selected node, LED, latency/uptime/session stats),
  an oscilloscope-style live traffic chart (60-sample ~90s history, download/upload
  traces), a session-at-a-glance quad (active connections, saved nodes, sing-box core
  version, rule-set last-updated), a recent-connections preview, and the **中国直连 / TUN
  / 系统代理** toggles + start/stop/test/delete/修复网络/实时日志 controls.
- **Nodes** — searchable/sortable/group-filterable node table with a two-letter protocol
  badge (VL/VM/TR/SS/HY/TU/SK/HT) and latency badge per row, paste-to-import (single link,
  multi-line list, or a subscription URL), and a full **node editor modal** covering every
  field for all 8 protocols (UUID/password/flow/security/method/obfs/congestion-control/
  TLS+Reality/transport type) — backed by `guderray-core`'s `OutboundDraft` round-trip
  layer, so editing a node can't silently drop or leak fields between protocols.
- **Connections** — live active-connection list from the Clash API (refreshed every 1.5s),
  filterable by route (全部/直连/代理/屏蔽 with live counts) and by host, with a per-row
  **disconnect** button and a **全部断开** bulk action.
- **Rules** — a 3-way routing-mode selector (**全局代理 / 中国直连 / 自定义**), a live
  **preview classifier** (type a domain, see which bucket + built-in CN heuristic it would
  hit — clearly labeled as an approximation, since the client has no local geosite/geoip
  data to match against), and chip-based add/remove editors for the 直连/代理/屏蔽 rule
  buckets (domains, IPs, and `process:`-prefixed process names, auto-classified).
- **Subscriptions** — add/update/remove subscriptions; removing one **keeps** the nodes it
  already imported.
- **Settings** — 开机自启 / 启动即连接, plus an **advanced settings** panel exposing 11
  fields that existed in `Settings` since the MVP but had no GUI form before: SOCKS
  port/listen address, Clash API port, direct/remote DNS, DNS strategy, TUN
  stack/MTU/strict-route, log level, and ad-blocking (geosite-category-ads-all). Most take
  effect on the *next* `up`, not by hot-reloading a running core.
- **系统托盘** with show/stop/quit; close-to-tray; **暗色/亮色**主题切换 (remembered);
  **中/EN** language toggle.
- **🩹 修复网络** button + a startup `reconcile` that auto-clears a stale system proxy left by a
  forced kill; a **watchdog** that auto-reconnects if the core dies (when 启动即连接/auto-restart on).
- First-run banner with a one-click **下载核心组件** (sing-box + wintun + rule-sets).

## Full CLI surface

```
profile add --link|--url|--file | list | show | remove | rename | edit | set-group
routing set <mode> | rule add|remove|clear|list
up <id> [--tun --sysproxy --elevate] | down | status | stats | connections
test | ping <id> | sub add|list|remove|update
tun on|off | sysproxy on|off | autostart on|off|status
repair | logs [--tail N] | assets sync [--version X]
```

## Config location

Resolved in this order:

1. `GUDERRAY_HOME=<dir>` env var, if set (highest priority — explicit override).
2. **Portable mode**: `<exe_dir>\data\` if a `data\` folder (or empty `portable` marker
   file) sits next to the running exe — this is what `scripts/package.ps1` sets up.
3. Otherwise `%APPDATA%\GuderRay\GuderRay\` (normal per-user install).

Inside that root: `profiles.json`, `settings.json`, `subscriptions.json`, `state.json`,
`assets/` (sing-box.exe, wintun.dll, `*.srs` rule-sets), `logs/`, `gen-config.json`.

[sing-box]: https://sing-box.sagernet.org

Packaging notes:

- `scripts/package.ps1` is Windows-only because it creates a portable Windows zip and can run
  `signtool`. Optional signing example:

```powershell
pwsh ./scripts/package.ps1 -SignTool "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe" -CertThumbprint "<thumbprint>"
```

- Unsigned builds may show Microsoft SmartScreen's "unknown publisher" warning. For personal
  builds, choose "More info" then "Run anyway"; public releases should be Authenticode-signed.
- On Linux/macOS, build from source with `cargo build --release`; packaging assets and system
  proxy behavior are platform-specific.