//! GuderRay GUI (Slint, Fluent style) — a thin shell over guderray-core + guderray-engine.
// windows_subsystem is unconditional: even debug builds must never own a console window.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod connections;
mod icon;
mod state;

use connections::map_connections;
use guderray_core::{draft_to_outbound, link, outbound_to_draft, Outbound, OutboundDraft, Paths, RoutingMode};
use slint::{
    CloseRequestResponse, ComponentHandle, Image, Model, ModelRc, SharedPixelBuffer, SharedString,
    Timer, TimerMode, VecModel,
};
use state::{AppState, SharedState};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, TrayIconEvent,
};

slint::include_modules!();

fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

fn fmt_rate(bps: f64) -> String {
    if bps >= 1024.0 * 1024.0 {
        format!("{:.1} MB/s", bps / 1024.0 / 1024.0)
    } else if bps >= 1024.0 {
        format!("{:.0} KB/s", bps / 1024.0)
    } else {
        format!("{:.0} B/s", bps.max(0.0))
    }
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Two-letter protocol badge for the Nodes table (mirrors the mockup's VL/VM/TR/... chips).
fn protocol_badge(o: &Outbound) -> &'static str {
    match o {
        Outbound::Vless(_) => "VL",
        Outbound::Vmess(_) => "VM",
        Outbound::Trojan(_) => "TR",
        Outbound::Shadowsocks(_) => "SS",
        Outbound::Hysteria2(_) => "HY",
        Outbound::Tuic(_) => "TU",
        Outbound::Socks(_) => "SK",
        Outbound::Http(_) => "HT",
        Outbound::Raw(_) => "??",
    }
}

/// Format an absolute byte count (e.g. a session traffic total), not a rate.
fn fmt_bytes(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} GB", b / 1024.0 / 1024.0 / 1024.0)
    } else if b >= 1024.0 * 1024.0 {
        format!("{:.1} MB", b / 1024.0 / 1024.0)
    } else if b >= 1024.0 {
        format!("{:.0} KB", b / 1024.0)
    } else {
        format!("{b:.0} B")
    }
}

/// Format an elapsed duration as a compact `H:MM:SS` uptime string.
fn fmt_uptime(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    format!("{}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// Compact, language-neutral "how long ago" badge (e.g. "3d", "5h", "<1h") for the
/// rule-set-updated quad cell — deliberately not routed through `Tr`/`apply_language`,
/// same precedent as the latency badge's bare "37ms" and the live speed text.
fn relative_short(then: SystemTime) -> String {
    let Ok(elapsed) = SystemTime::now().duration_since(then) else {
        return "—".to_string();
    };
    let secs = elapsed.as_secs();
    if secs < 3600 {
        "<1h".to_string()
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Relative-time badge for the last CN rule-set download, read straight off
/// `geosite-cn.srs`'s mtime — a real filesystem fact, not a tracked-and-possibly-stale field.
fn ruleset_updated_text(paths: &Paths) -> String {
    let path = paths.assets_dir().join("geosite-cn.srs");
    match std::fs::metadata(&path).and_then(|m| m.modified()) {
        Ok(t) => relative_short(t),
        Err(_) => "—".to_string(),
    }
}

/// Build oscilloscope-chart SVG path-command strings (0..100 viewbox) from the raw
/// (download-rate, upload-rate) history. Slint's `Path` element doesn't support `for`
/// loops over its sub-elements (github.com/slint-ui/slint/issues/754 — hit this directly
/// while wiring this chart), so the path is built here as a plain string instead.
/// Returns (download-fill-area, download-stroke, upload-stroke, has-data).
fn build_chart_paths(hist: &VecDeque<(f64, f64)>) -> (String, String, String, bool) {
    if hist.len() < 2 {
        return (String::new(), String::new(), String::new(), false);
    }
    let peak = hist.iter().flat_map(|(d, u)| [*d, *u]).fold(1.0_f64, f64::max);
    let n = hist.len();
    let point = |i: usize, v: f64| {
        let x = i as f64 / (n - 1) as f64 * 100.0;
        let y = 100.0 - (v / peak * 100.0).clamp(0.0, 100.0);
        (x, y)
    };
    let mut down_stroke = String::new();
    let mut up_stroke = String::new();
    for (i, (d, u)) in hist.iter().enumerate() {
        let (xd, yd) = point(i, *d);
        let (xu, yu) = point(i, *u);
        let cmd = if i == 0 { "M" } else { "L" };
        down_stroke.push_str(&format!("{cmd} {xd:.2} {yd:.2} "));
        up_stroke.push_str(&format!("{cmd} {xu:.2} {yu:.2} "));
    }
    let down_stroke = down_stroke.trim_end().to_string();
    let up_stroke = up_stroke.trim_end().to_string();
    // reuse the stroke's own points as `L`s (dropping its leading "M") so the fill
    // outline is a single subpath: bottom-left -> trace across -> bottom-right -> close.
    let down_fill = format!(
        "M 0 100 L {} L 100 100 Z",
        down_stroke.strip_prefix("M ").unwrap_or(&down_stroke)
    );
    (down_fill, down_stroke, up_stroke, true)
}

#[cfg(test)]
mod chart_tests {
    use super::*;

    #[test]
    fn fewer_than_two_samples_yields_no_data() {
        let mut hist = VecDeque::new();
        assert_eq!(build_chart_paths(&hist), (String::new(), String::new(), String::new(), false));
        hist.push_back((10.0, 5.0));
        assert_eq!(build_chart_paths(&hist), (String::new(), String::new(), String::new(), false));
    }

    #[test]
    fn two_samples_produce_a_move_and_a_line_spanning_the_full_width() {
        let mut hist = VecDeque::new();
        hist.push_back((0.0, 0.0));
        hist.push_back((100.0, 50.0));
        let (fill, down_stroke, up_stroke, has_data) = build_chart_paths(&hist);
        assert!(has_data);
        assert!(down_stroke.starts_with("M 0.00 100.00"));
        assert!(down_stroke.ends_with("L 100.00 0.00"));
        assert!(up_stroke.ends_with("L 100.00 50.00"));
        assert!(fill.starts_with("M 0 100 L 0.00 100.00"));
        assert!(fill.ends_with("L 100 100 Z"));
    }
}

/// Read the last `n` lines of the sing-box log, stripping ANSI color codes.
fn tail_log(paths: &Paths, n: usize) -> String {
    let path = paths.logs_dir().join("sing-box.log");
    let Ok(s) = std::fs::read_to_string(&path) else {
        return "（暂无日志）".into();
    };
    // strip ANSI escape sequences: ESC [ ... m
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            while let Some(&nc) = chars.peek() {
                chars.next();
                if nc.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    let lines: Vec<&str> = out.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Set every UI string in the `Tr` global for the given language ("zh" or "en").
fn apply_language(win: &MainWindow, lang: &str) {
    let en = lang == "en";
    let tr = win.global::<Tr>();
    macro_rules! t {
        ($setter:ident, $zh:expr, $en:expr) => {
            tr.$setter(SharedString::from(if en { $en } else { $zh }));
        };
    }
    t!(set_not_running, "未运行", "Stopped");
    t!(set_running_prefix, "运行中 · ", "Running · ");
    t!(set_ready_hint, "GuderRay 就绪。选择一个节点后点击「启动」。", "GuderRay ready. Select a node and click Start.");
    t!(set_back, "返回", "Back");
    t!(set_settings, "设置", "Settings");
    t!(set_lang_btn, "EN", "中");
    t!(set_nodes_prefix, "节点 · ", "Nodes · ");
    t!(set_nodes_suffix, " 个", "");
    t!(set_test_all, "测速全部", "Test All");
    t!(set_paste_ph, "粘贴链接/订阅URL，回车导入…", "Paste link / subscription URL, Enter to import…");
    t!(set_rename_ph, "重命名选中节点…", "Rename selected node…");
    t!(set_rename, "重命名", "Rename");
    t!(set_timeout, "超时", "timeout");
    t!(set_core_missing, "核心组件未就绪", "Core components not ready");
    t!(set_core_missing_desc, "首次使用需下载 sing-box 内核、wintun 驱动与中国直连规则集 (~45MB)", "First run needs sing-box core, wintun driver and CN rule-sets (~45MB)");
    t!(set_downloading, "下载中…", "Downloading…");
    t!(set_download_core, "下载核心组件", "Download core");
    t!(set_routing_ctrl, "分流控制", "Routing");
    t!(set_cn_direct, "中国直连", "China Direct");
    t!(set_cn_direct_desc, "geosite-cn / geoip-cn 直连，其余走代理", "geosite-cn / geoip-cn direct, rest via proxy");
    t!(set_tun_mode, "TUN 模式", "TUN Mode");
    t!(set_tun_desc, "接管系统路由，需要管理员权限", "Takes over system routing, needs admin");
    t!(set_sysproxy, "系统代理", "System Proxy");
    t!(set_sysproxy_desc, "设置 Windows 系统代理指向本地端口", "Point the Windows system proxy at the local port");
    t!(set_start, "启动", "Start");
    t!(set_stop, "停止", "Stop");
    t!(set_test, "测速", "Test");
    t!(set_del, "删除", "Delete");
    t!(set_repair, "修复网络", "Repair Net");
    t!(set_livelog_on, "实时日志·开", "Live Log·On");
    t!(set_livelog, "实时日志", "Live Log");
    t!(set_sub_mgmt, "订阅管理", "Subscriptions");
    t!(set_sub_empty, "暂无订阅", "No subscriptions yet");
    t!(set_sub_name_ph, "订阅名称", "Name");
    t!(set_sub_url_ph, "订阅链接 URL", "Subscription URL");
    t!(set_sub_add, "添加/更新", "Add/Update");
    t!(set_sub_update_all, "全部更新", "Update All");
    t!(set_remove, "删除", "Delete");
    t!(set_rules_title, "自定义路由规则", "Custom Routing Rules");
    t!(set_rules_desc, "每行一条。域名或 IP/CIDR 自动分层；进程名用前缀 process:（如 process:wechat.exe）。支持 geosite: / geoip: / domain: 等前缀。", "One per line. Domains or IP/CIDR auto-classified; process names use the process: prefix (e.g. process:wechat.exe). Supports geosite: / geoip: / domain: prefixes.");
    t!(set_bucket_direct, "直连", "Direct");
    t!(set_bucket_proxy, "代理", "Proxy");
    t!(set_bucket_block, "屏蔽", "Block");
    t!(set_general, "通用设置", "General");
    t!(set_autostart, "开机自启", "Launch at Boot");
    t!(set_autostart_desc, "登录 Windows 时自动启动 GuderRay", "Start GuderRay when you log in to Windows");
    t!(set_autoconnect, "启动即连接", "Auto-connect");
    t!(set_autoconnect_desc, "打开程序时自动连接上次使用的节点", "Connect the last node on launch");
    t!(set_nav_dashboard, "仪表盘", "Dashboard");
    t!(set_nav_nodes, "节点", "Nodes");
    t!(set_nav_connections, "连接", "Connections");
    t!(set_nav_rules, "规则", "Rules");
    t!(set_nav_subs, "订阅", "Subscriptions");
    t!(set_coming_soon, "即将推出", "Coming soon");
    t!(set_no_node_selected, "未选择节点", "No node selected");
    t!(set_hero_latency, "延迟", "Latency");
    t!(set_hero_uptime, "运行时长", "Uptime");
    t!(set_hero_session, "本次会话", "Session");
    t!(set_hero_test_all, "测速全部节点", "Test all nodes");
    t!(set_hero_view_conns, "查看连接", "View connections");
    t!(set_chart_legend_down, "下载", "Download");
    t!(set_chart_legend_up, "上传", "Upload");
    t!(set_chart_window, "近 90 秒", "last 90s");
    t!(
        set_chart_empty,
        "启动节点后这里会显示实时流量",
        "Traffic shows here once a node is running"
    );
    t!(set_quad_title, "本次概览", "Session at a glance");
    t!(set_quad_active_conns, "活跃连接", "Active connections");
    t!(set_quad_saved_nodes, "已保存节点", "Saved nodes");
    t!(set_quad_core_version, "sing-box 内核", "sing-box core");
    t!(set_quad_ruleset, "规则集更新", "Rule-set updated");
    t!(set_recent_conns_title, "最近连接", "Recent connections");
    t!(set_recent_conns_view_all, "查看全部", "View all");
    t!(set_recent_conns_empty, "暂无活跃连接", "No active connections");
    t!(set_node_search_ph, "搜索节点…", "Search nodes…");
    t!(set_node_filter_all, "全部", "All");
    t!(set_node_sort_latency, "延迟排序", "Sort · Latency");
    t!(set_node_sort_name, "名称排序", "Sort · Name");
    t!(set_node_sort_group, "分组排序", "Sort · Group");
    t!(set_node_col_node, "节点", "Node");
    t!(set_node_col_server, "服务器", "Server");
    t!(set_node_col_latency, "延迟", "Latency");
    t!(set_node_add, "添加节点", "Add node");
    t!(
        set_node_import_ph,
        "粘贴分享链接或订阅 URL，回车导入…",
        "Paste a share link or subscription URL, press Enter…"
    );
    t!(set_node_import, "导入", "Import");
    t!(set_node_empty, "暂无节点", "No nodes yet");
    t!(set_node_edit_title, "编辑节点", "Edit node");
    t!(set_node_add_title, "新建节点", "Add node");
    t!(set_node_field_name, "名称", "Name");
    t!(set_node_field_group, "分组", "Group");
    t!(set_node_field_protocol, "协议", "Protocol");
    t!(set_node_field_server, "服务器地址", "Server");
    t!(set_node_field_port, "端口", "Port");
    t!(set_node_field_uuid, "UUID", "UUID");
    t!(set_node_field_password, "密码", "Password");
    t!(set_node_field_flow, "Flow", "Flow");
    t!(set_node_field_packet_encoding, "Packet Encoding", "Packet Encoding");
    t!(set_node_field_alter_id, "Alter ID", "Alter ID");
    t!(set_node_field_security, "加密方式", "Security");
    t!(set_node_field_method, "加密方法", "Method");
    t!(set_node_field_obfs, "混淆类型", "Obfs");
    t!(set_node_field_obfs_password, "混淆密码", "Obfs Password");
    t!(set_node_field_congestion, "拥塞控制", "Congestion Control");
    t!(set_node_field_username, "用户名", "Username");
    t!(set_node_field_tls, "启用 TLS", "Enable TLS");
    t!(set_node_field_sni, "SNI", "SNI");
    t!(set_node_field_insecure, "跳过证书校验", "Skip cert verify");
    t!(set_node_field_alpn, "ALPN（逗号分隔）", "ALPN (comma-separated)");
    t!(set_node_field_fingerprint, "指纹", "Fingerprint");
    t!(set_node_field_reality_pbk, "Reality 公钥", "Reality Public Key");
    t!(set_node_field_reality_sid, "Reality Short ID", "Reality Short ID");
    t!(set_node_field_transport, "传输层", "Transport");
    t!(set_node_field_ws_path, "WS 路径", "WS Path");
    t!(set_node_field_ws_host, "WS Host", "WS Host");
    t!(set_node_field_grpc_service, "gRPC 服务名", "gRPC Service Name");
    t!(set_node_field_http_host, "HTTP Host（逗号分隔）", "HTTP Host (comma-separated)");
    t!(set_node_field_http_path, "HTTP 路径", "HTTP Path");
    t!(set_node_field_httpupgrade_path, "HTTPUpgrade 路径", "HTTPUpgrade Path");
    t!(set_node_field_httpupgrade_host, "HTTPUpgrade Host", "HTTPUpgrade Host");
    t!(set_node_save, "保存", "Save");
    t!(set_node_cancel, "取消", "Cancel");
    t!(
        set_node_raw_notice,
        "该节点来自导入的原始配置，暂不支持在此编辑。",
        "This node came from a raw imported config and can't be edited here."
    );
    t!(
        set_node_editor_error_required,
        "请填写服务器地址、端口，以及该协议要求的必填项。",
        "Fill in the server, port, and any fields this protocol requires."
    );
    t!(set_conn_search_ph, "按域名筛选…", "Filter by host…");
    t!(set_conn_filter_all, "全部", "All");
    t!(set_conn_filter_direct, "直连", "Direct");
    t!(set_conn_filter_proxy, "代理", "Proxy");
    t!(set_conn_filter_block, "屏蔽", "Blocked");
    t!(set_conn_col_host, "目标", "Host");
    t!(set_conn_col_route, "路由", "Route");
    t!(set_conn_col_duration, "时长", "Duration");
    t!(set_conn_close_all, "全部断开", "Close all");
    t!(set_conn_empty, "暂无活跃连接", "No active connections");
    t!(
        set_conn_live_hint,
        "数据来自 Clash API，每 1.5 秒刷新一次",
        "Live from the Clash API, refreshed every 1.5s"
    );
    t!(set_rules_mode_global, "全局代理", "Global proxy");
    t!(set_rules_mode_cn_direct, "中国直连", "China direct");
    t!(set_rules_mode_custom, "自定义", "Custom");
    t!(set_rules_preview_title, "预览分类", "Preview classification");
    t!(set_rules_preview_ph, "输入域名，如 chatgpt.com", "Enter a domain, e.g. chatgpt.com");
    t!(
        set_rules_preview_caveat,
        "仅模拟你自己添加的规则；不模拟内置地理规则库（geosite/geoip 数据在本机不可用），中国直连模式下的启发式仅按 .cn 后缀粗略近似，并非精确结果。",
        "Only simulates rules you've added yourself; the built-in geosite/geoip rule-sets aren't available locally to simulate, and the China-direct heuristic is a crude .cn-suffix approximation, not an exact result."
    );
    t!(
        set_rules_add_ph,
        "添加域名 / IP / process:进程名，回车确认…",
        "Add a domain / IP / process:name, press Enter…"
    );
    t!(set_settings_advanced_title, "高级设置", "Advanced settings");
    t!(
        set_settings_restart_hint,
        "以下设置在下次启动代理时生效，不会热更新正在运行的核心。",
        "These settings take effect the next time the proxy starts — they don't hot-reload a running core."
    );
    t!(set_settings_save, "保存高级设置", "Save advanced settings");
    t!(set_settings_field_socks_port, "SOCKS 端口", "SOCKS port");
    t!(set_settings_field_socks_listen, "SOCKS 监听地址", "SOCKS listen address");
    t!(set_settings_field_clash_api_port, "Clash API 端口", "Clash API port");
    t!(set_settings_field_direct_dns, "国内 DNS", "Direct DNS");
    t!(set_settings_field_remote_dns, "远程 DNS", "Remote DNS");
    t!(set_settings_field_dns_strategy, "DNS 解析策略", "DNS strategy");
    t!(set_settings_field_tun_stack, "TUN 协议栈", "TUN stack");
    t!(set_settings_field_tun_mtu, "TUN MTU", "TUN MTU");
    t!(set_settings_field_tun_strict_route, "TUN 严格路由", "TUN strict route");
    t!(set_settings_field_log_level, "日志级别", "Log level");
    t!(
        set_settings_field_block_ads,
        "屏蔽广告（geosite-category-ads-all）",
        "Block ads (geosite-category-ads-all)"
    );
}

fn slint_icon() -> Image {
    let (rgba, w, h) = icon::rgba();
    let mut pb = SharedPixelBuffer::<slint::Rgba8Pixel>::new(w, h);
    pb.make_mut_bytes().copy_from_slice(&rgba);
    Image::from_rgba8(pb)
}

/// Rebuild the profile list from the in-memory cache (no disk I/O).
fn rebuild_profiles(win: &MainWindow, st: &AppState) {
    let rows: Vec<ProfileRow> = st
        .profiles
        .profiles
        .iter()
        .map(|p| {
            let (server, port) = p.server_endpoint();
            ProfileRow {
                id: p.id as i32,
                name: SharedString::from(p.name.clone()),
                endpoint: SharedString::from(format!("{server}:{port}")),
                group: SharedString::from(p.group.clone().unwrap_or_default()),
                latency: p.latency.unwrap_or(-1),
                protocol_badge: SharedString::from(protocol_badge(&p.outbound)),
            }
        })
        .collect();
    win.set_profiles(ModelRc::new(VecModel::from(rows.clone())));
    refresh_nodes_view(win, &rows);
}

/// Recompute the Nodes view's filtered/sorted row list and its group-chip list from the
/// full row set, using the current search/filter/sort state already bound on `win`. Kept
/// separate from `profiles` (see that property's doc comment) so Nodes-view filtering
/// never touches the Dashboard sidebar/hero.
fn refresh_nodes_view(win: &MainWindow, all_rows: &[ProfileRow]) {
    let mut groups: Vec<String> =
        all_rows.iter().map(|r| r.group.to_string()).filter(|g| !g.is_empty()).collect();
    groups.sort();
    groups.dedup();
    win.set_nodes_groups(ModelRc::new(VecModel::from(
        groups.into_iter().map(SharedString::from).collect::<Vec<_>>(),
    )));

    let search = win.get_nodes_search().to_string().to_lowercase();
    let group_filter = win.get_nodes_group_filter().to_string();
    let mut rows: Vec<ProfileRow> = all_rows
        .iter()
        .filter(|r| {
            let matches_search = search.is_empty()
                || r.name.to_lowercase().contains(&search)
                || r.endpoint.to_lowercase().contains(&search);
            let matches_group = group_filter.is_empty() || r.group == group_filter;
            matches_search && matches_group
        })
        .cloned()
        .collect();
    match win.get_nodes_sort_mode().as_str() {
        "name" => rows.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        "group" => {
            rows.sort_by(|a, b| a.group.to_lowercase().cmp(&b.group.to_lowercase()).then(a.name.cmp(&b.name)))
        }
        _ => rows.sort_by_key(|r| if r.latency < 0 { i32::MAX } else { r.latency }),
    }
    win.set_nodes_view_rows(ModelRc::new(VecModel::from(rows)));
}

/// `NodeDraft` (Slint, generated by slint_build) <-> `OutboundDraft` (guderray-core) —
/// same field set, different int widths (Slint has no u16/u32) and case convention.
fn node_draft_to_core(d: &NodeDraft) -> OutboundDraft {
    OutboundDraft {
        protocol: d.protocol.to_string(),
        server: d.server.to_string(),
        port: d.port.clamp(0, u16::MAX as i32) as u16,
        uuid: d.uuid.to_string(),
        password: d.password.to_string(),
        flow: d.flow.to_string(),
        packet_encoding: d.packet_encoding.to_string(),
        alter_id: d.alter_id.clamp(0, u32::MAX as i32) as u32,
        security: d.security.to_string(),
        method: d.method.to_string(),
        obfs: d.obfs.to_string(),
        obfs_password: d.obfs_password.to_string(),
        congestion_control: d.congestion_control.to_string(),
        username: d.username.to_string(),
        tls_enabled: d.tls_enabled,
        sni: d.sni.to_string(),
        insecure: d.insecure,
        alpn: d.alpn.to_string(),
        fingerprint: d.fingerprint.to_string(),
        reality_public_key: d.reality_public_key.to_string(),
        reality_short_id: d.reality_short_id.to_string(),
        transport_type: d.transport_type.to_string(),
        ws_path: d.ws_path.to_string(),
        ws_host: d.ws_host.to_string(),
        grpc_service_name: d.grpc_service_name.to_string(),
        http_host: d.http_host.to_string(),
        http_path: d.http_path.to_string(),
        httpupgrade_path: d.httpupgrade_path.to_string(),
        httpupgrade_host: d.httpupgrade_host.to_string(),
    }
}

fn core_draft_to_node(d: &OutboundDraft) -> NodeDraft {
    NodeDraft {
        protocol: SharedString::from(d.protocol.clone()),
        server: SharedString::from(d.server.clone()),
        port: d.port as i32,
        uuid: SharedString::from(d.uuid.clone()),
        password: SharedString::from(d.password.clone()),
        flow: SharedString::from(d.flow.clone()),
        packet_encoding: SharedString::from(d.packet_encoding.clone()),
        alter_id: d.alter_id as i32,
        security: SharedString::from(d.security.clone()),
        method: SharedString::from(d.method.clone()),
        obfs: SharedString::from(d.obfs.clone()),
        obfs_password: SharedString::from(d.obfs_password.clone()),
        congestion_control: SharedString::from(d.congestion_control.clone()),
        username: SharedString::from(d.username.clone()),
        tls_enabled: d.tls_enabled,
        sni: SharedString::from(d.sni.clone()),
        insecure: d.insecure,
        alpn: SharedString::from(d.alpn.clone()),
        fingerprint: SharedString::from(d.fingerprint.clone()),
        reality_public_key: SharedString::from(d.reality_public_key.clone()),
        reality_short_id: SharedString::from(d.reality_short_id.clone()),
        transport_type: SharedString::from(d.transport_type.clone()),
        ws_path: SharedString::from(d.ws_path.clone()),
        ws_host: SharedString::from(d.ws_host.clone()),
        grpc_service_name: SharedString::from(d.grpc_service_name.clone()),
        http_host: SharedString::from(d.http_host.clone()),
        http_path: SharedString::from(d.http_path.clone()),
        httpupgrade_path: SharedString::from(d.httpupgrade_path.clone()),
        httpupgrade_host: SharedString::from(d.httpupgrade_host.clone()),
    }
}

/// Populate the settings view (subscription list) from the in-memory cache.
fn load_settings_view(win: &MainWindow, st: &AppState) {
    let rows: Vec<SubRow> = st
        .subs
        .subs
        .iter()
        .map(|s| SubRow {
            name: SharedString::from(s.name.clone()),
            url: SharedString::from(s.url.clone()),
        })
        .collect();
    win.set_subscriptions(ModelRc::new(VecModel::from(rows)));
}

/// Populate the Settings view's advanced-fields draft from the in-memory cache. This is
/// a batch-edit draft (see the properties' own doc comment in main.slint) — deliberately
/// re-read every time the Settings view opens so it can't go stale relative to the CLI.
fn refresh_advanced_settings(win: &MainWindow, st: &AppState) {
    win.set_settings_socks_port(st.settings.socks_port as i32);
    win.set_settings_socks_listen(SharedString::from(st.settings.socks_listen.clone()));
    win.set_settings_clash_api_port(st.settings.clash_api_port as i32);
    win.set_settings_direct_dns(SharedString::from(st.settings.direct_dns.clone()));
    win.set_settings_remote_dns(SharedString::from(st.settings.remote_dns.clone()));
    win.set_settings_dns_strategy(SharedString::from(st.settings.dns_strategy.clone()));
    win.set_settings_tun_stack(SharedString::from(st.settings.tun_stack.clone()));
    win.set_settings_tun_mtu(st.settings.tun_mtu as i32);
    win.set_settings_tun_strict_route(st.settings.tun_strict_route);
    win.set_settings_log_level(SharedString::from(st.settings.log_level.clone()));
    win.set_settings_block_ads(st.settings.block_ads);
}

/// Populate the Rules view's chip lists + routing-mode selector from the in-memory
/// cache. No disk I/O, no special "load on open" step (Phase 6 follows the same
/// always-in-sync pattern 0c established for Settings) — called at startup and after
/// every rule add/remove/routing-mode change.
fn refresh_rules_view(win: &MainWindow, st: &AppState) {
    let to_chips = |list: &guderray_core::RuleList| -> Vec<SharedString> {
        list.to_lines().lines().map(SharedString::from).collect()
    };
    win.set_rules_direct_chips(ModelRc::new(VecModel::from(to_chips(&st.settings.user_rules.direct))));
    win.set_rules_proxy_chips(ModelRc::new(VecModel::from(to_chips(&st.settings.user_rules.proxy))));
    win.set_rules_block_chips(ModelRc::new(VecModel::from(to_chips(&st.settings.user_rules.block))));
    win.set_routing_mode(SharedString::from(match st.settings.routing {
        RoutingMode::Global => "global",
        RoutingMode::CnDirect => "cn-direct",
        RoutingMode::Custom => "custom",
    }));
}

/// Poll engine status into the window's bound properties. `State` (the running-process
/// record) is intentionally NOT part of `AppState` — it's read fresh from disk here since
/// the CLI can also start/stop the core out from under the GUI.
fn apply_status(win: &MainWindow, paths: &Paths) {
    match guderray_engine::status(paths) {
        Ok(v) => {
            let running = v["running"].as_bool().unwrap_or(false);
            win.set_is_running(running);
            win.set_active_profile_name(SharedString::from(
                v["profile"]["name"].as_str().unwrap_or("").to_string(),
            ));
            win.set_core_version_text(SharedString::from(
                v["core_version"].as_str().unwrap_or("—").to_string(),
            ));
            win.set_status_summary(SharedString::from(pretty(&v)));
        }
        Err(e) => {
            win.set_is_running(false);
            win.set_core_version_text(SharedString::from("—"));
            win.set_status_summary(SharedString::from(format!("status error: {e}")));
        }
    }
}

// ---------------------------------------------------------------------------
// Callback wiring, grouped by feature area. Split out of `main()` (previously one
// ~700-line function with 30+ nested closures) because a function that large crashed
// rustc's LLVM backend in debug builds (STATUS_STACK_BUFFER_OVERRUN during MIR
// building's drop-scope analysis — reproduced consistently; release builds, which
// don't hit the same codegen path, were unaffected). Each group is independent and
// self-contained: every closure still does its own `win.as_weak()`/`paths.clone()`/
// `state.clone()` exactly as it did inline in `main()`, just inside a named function.
// ---------------------------------------------------------------------------

/// Node selection, connect/disconnect lifecycle, import, rename, delete, test-all.
fn wire_profile_callbacks(win: &MainWindow, paths: &Paths, state: &SharedState) {
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_select(move |id| {
            if let Some(w) = w.upgrade() {
                w.set_selected_id(id);
            }
            let mut st = state::lock(&state);
            st.settings.last_profile_id = Some(id as u32);
            let _ = st.save_settings();
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        let state = state.clone();
        win.on_refresh(move || {
            if let Some(w) = w.upgrade() {
                // "refresh" is the one explicit, user-triggered moment where re-reading
                // disk is correct — it exists precisely to pick up changes made by the
                // CLI (or another process) while the GUI was open.
                let _ = state::lock(&state).reload();
                let st = state::lock(&state);
                rebuild_profiles(&w, &st);
                drop(st);
                apply_status(&w, &paths);
            }
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        win.on_start_selected(move || {
            if let Some(w) = w.upgrade() {
                let id = w.get_selected_id();
                if id < 0 {
                    w.set_log_text(SharedString::from("请先在左侧选择一个节点。"));
                    return;
                }
                let tun = Some(w.get_tun());
                let sp = Some(w.get_sysproxy());
                let msg = match guderray_engine::up(&paths, id as u32, tun, sp) {
                    Ok(v) => format!("已启动:\n{}", pretty(&v)),
                    Err(e) => format!("启动失败: {e}"),
                };
                w.set_log_text(SharedString::from(msg));
                apply_status(&w, &paths);
            }
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        win.on_stop_proxy(move || {
            if let Some(w) = w.upgrade() {
                let msg = match guderray_engine::down(&paths) {
                    Ok(v) => format!("已停止:\n{}", pretty(&v)),
                    Err(e) => format!("停止失败: {e}"),
                };
                w.set_log_text(SharedString::from(msg));
                apply_status(&w, &paths);
            }
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        win.on_ping_selected(move || {
            if let Some(w) = w.upgrade() {
                let id = w.get_selected_id();
                if id < 0 {
                    w.set_log_text(SharedString::from("请先在左侧选择一个节点。"));
                    return;
                }
                let msg = match guderray_engine::ping_profile(&paths, id as u32, 3000) {
                    Ok(v) => format!("测速结果:\n{}", pretty(&v)),
                    Err(e) => format!("测速失败: {e}"),
                };
                w.set_log_text(SharedString::from(msg));
            }
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        let state = state.clone();
        win.on_add_link(move |text| {
            let text = text.trim().to_string();
            if text.is_empty() {
                return;
            }
            let Some(w) = w.upgrade() else { return };

            // http(s):// with no newline → treat as a subscription URL (fetch on a thread)
            let is_sub_url =
                (text.starts_with("http://") || text.starts_with("https://")) && !text.contains('\n');
            if is_sub_url {
                w.set_log_text(SharedString::from("正在拉取订阅…"));
                let w2 = w.as_weak();
                let paths = paths.clone();
                let state = state.clone();
                std::thread::spawn(move || {
                    // profile_add_url is an engine-layer function: it does its own
                    // ProfileStore disk I/O, so the cache must be reloaded afterward
                    // rather than written through from here.
                    let r = guderray_engine::profile_add_url(&paths, &text, None);
                    let state2 = state.clone();
                    let _ = w2.upgrade_in_event_loop(move |win| {
                        win.set_log_text(SharedString::from(match &r {
                            Ok(v) => format!("已从订阅导入 {} 个节点", v["count"].as_u64().unwrap_or(0)),
                            Err(e) => format!("订阅导入失败: {e}"),
                        }));
                        let _ = state::lock(&state2).reload();
                        rebuild_profiles(&win, &state::lock(&state2));
                    });
                });
                return;
            }

            // multi-line paste → parse as a link list; single line → one link
            let msg = (|| -> anyhow::Result<String> {
                let mut st = state::lock(&state);
                if text.contains('\n') {
                    let nodes = guderray_core::sub::parse_subscription(&text);
                    if nodes.is_empty() {
                        anyhow::bail!("未解析到任何节点");
                    }
                    let n = nodes.len();
                    for (name, ob) in nodes {
                        let nm = if name.is_empty() { "unnamed".into() } else { name };
                        st.profiles.add(nm, None, ob);
                    }
                    st.save_profiles()?;
                    Ok(format!("已批量导入 {n} 个节点"))
                } else {
                    let (name, ob) = link::parse_link(&text).map_err(|e| anyhow::anyhow!("{e}"))?;
                    let nm = if name.is_empty() { "unnamed".into() } else { name };
                    let id = st.profiles.add(nm.clone(), None, ob);
                    st.save_profiles()?;
                    Ok(format!("已导入节点 #{id}: {nm}"))
                }
            })();
            w.set_log_text(SharedString::from(match msg {
                Ok(s) => s,
                Err(e) => format!("导入失败: {e}"),
            }));
            rebuild_profiles(&w, &state::lock(&state));
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_rename_selected(move |name| {
            let name = name.trim().to_string();
            let Some(w) = w.upgrade() else { return };
            let id = w.get_selected_id();
            if id < 0 {
                w.set_log_text(SharedString::from("请先在左侧选择要重命名的节点。"));
                return;
            }
            if name.is_empty() {
                w.set_log_text(SharedString::from("请输入新名称。"));
                return;
            }
            let msg = (|| -> anyhow::Result<String> {
                let mut st = state::lock(&state);
                st.profiles.rename(id as u32, name.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
                st.save_profiles()?;
                Ok(format!("已重命名节点 #{id} → {name}"))
            })();
            w.set_log_text(SharedString::from(match msg {
                Ok(s) => s,
                Err(e) => format!("重命名失败: {e}"),
            }));
            rebuild_profiles(&w, &state::lock(&state));
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        win.on_repair_network(move || {
            let msg = match guderray_engine::repair_network(&paths) {
                Ok(v) => format!("网络已修复（清系统代理 + 清理残留进程）:\n{}", pretty(&v)),
                Err(e) => format!("修复失败: {e}"),
            };
            if let Some(w) = w.upgrade() {
                w.set_log_text(SharedString::from(msg));
                apply_status(&w, &paths);
            }
        });
    }
    {
        win.on_toggle_live_log(move |_on| {
            // just a flag; the status timer tails the log when on. Clear when off.
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_delete_selected(move || {
            if let Some(w) = w.upgrade() {
                let id = w.get_selected_id();
                if id < 0 {
                    w.set_log_text(SharedString::from("请先在左侧选择要删除的节点。"));
                    return;
                }
                let msg = (|| -> anyhow::Result<String> {
                    let mut st = state::lock(&state);
                    st.profiles.remove(id as u32).map_err(|e| anyhow::anyhow!("{e}"))?;
                    st.save_profiles()?;
                    Ok(format!("已删除节点 #{id}"))
                })();
                let out = match msg {
                    Ok(s) => {
                        w.set_selected_id(-1);
                        s
                    }
                    Err(e) => format!("删除失败: {e}"),
                };
                w.set_log_text(SharedString::from(out));
                rebuild_profiles(&w, &state::lock(&state));
            }
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        let state = state.clone();
        win.on_test_all(move || {
            if let Some(w) = w.upgrade() {
                w.set_log_text(SharedString::from("正在并发测速全部节点…"));
            }
            let ids: Vec<u32> = state::lock(&state).profiles.profiles.iter().map(|p| p.id).collect();
            for id in ids {
                let paths = paths.clone();
                let w = w.clone();
                let state = state.clone();
                std::thread::spawn(move || {
                    // ping_profile is an engine-layer function: it persists latency to
                    // profiles.json itself. Mirror the result into the in-memory cache
                    // too (not just the Slint model), otherwise an unrelated later save
                    // from this process (e.g. a rename) would overwrite it with a stale
                    // in-memory copy and clobber what ping_profile just wrote to disk.
                    let ms: i32 = match guderray_engine::ping_profile(&paths, id, 2500) {
                        Ok(v) if v["reachable"].as_bool().unwrap_or(false) => {
                            v["delay_ms"].as_i64().unwrap_or(-2) as i32
                        }
                        _ => -2,
                    };
                    let _ = w.upgrade_in_event_loop(move |win| {
                        if let Ok(mut st) = state.try_lock() {
                            let _ = st.profiles.set_latency(id, Some(ms), Some(now_unix()));
                        }
                        let rows: Vec<ProfileRow> = win
                            .get_profiles()
                            .iter()
                            .map(|mut r: ProfileRow| {
                                if r.id == id as i32 {
                                    r.latency = ms;
                                }
                                r
                            })
                            .collect();
                        win.set_profiles(ModelRc::new(VecModel::from(rows)));
                    });
                });
            }
        });
    }
}

/// Nodes-view search/filter/sort + the node editor modal (Phase 4).
fn wire_node_callbacks(win: &MainWindow, state: &SharedState) {
    {
        let w = win.as_weak();
        win.on_nodes_filter_changed(move || {
            if let Some(w) = w.upgrade() {
                refresh_nodes_view(&w, &w.get_profiles().iter().collect::<Vec<_>>());
            }
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_delete_node(move |id| {
            if let Some(w) = w.upgrade() {
                let msg = (|| -> anyhow::Result<String> {
                    let mut st = state::lock(&state);
                    st.profiles.remove(id as u32).map_err(|e| anyhow::anyhow!("{e}"))?;
                    st.save_profiles()?;
                    Ok(format!("已删除节点 #{id}"))
                })();
                let out = match msg {
                    Ok(s) => {
                        if w.get_selected_id() == id {
                            w.set_selected_id(-1);
                        }
                        s
                    }
                    Err(e) => format!("删除失败: {e}"),
                };
                w.set_log_text(SharedString::from(out));
                rebuild_profiles(&w, &state::lock(&state));
            }
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_open_node_editor(move |id| {
            let Some(w) = w.upgrade() else { return };
            if id < 0 {
                // "add node": start from a blank vless draft — the most common protocol.
                w.set_node_draft(core_draft_to_node(&OutboundDraft {
                    protocol: "vless".into(),
                    ..Default::default()
                }));
            } else {
                let st = state::lock(&state);
                match st.profiles.get(id as u32) {
                    Ok(p) => w.set_node_draft(core_draft_to_node(&outbound_to_draft(&p.outbound))),
                    Err(_) => return,
                }
            }
            w.set_node_editor_id(id);
            w.set_node_editor_error(SharedString::from(""));
            w.set_node_editor_open(true);
        });
    }
    {
        let w = win.as_weak();
        win.on_close_node_editor(move || {
            if let Some(w) = w.upgrade() {
                w.set_node_editor_open(false);
            }
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_save_node_editor(move || {
            let Some(w) = w.upgrade() else { return };
            let id = w.get_node_editor_id();
            let core_draft = node_draft_to_core(&w.get_node_draft());
            let outbound = match draft_to_outbound(&core_draft) {
                Ok(o) => o,
                Err(e) => {
                    w.set_node_editor_error(SharedString::from(e));
                    return;
                }
            };
            let msg = (|| -> anyhow::Result<String> {
                let mut st = state::lock(&state);
                if id < 0 {
                    let name = if core_draft.server.is_empty() {
                        "unnamed".to_string()
                    } else {
                        format!("{}:{}", core_draft.server, core_draft.port)
                    };
                    let new_id = st.profiles.add(name.clone(), None, outbound);
                    st.save_profiles()?;
                    Ok(format!("已添加节点 #{new_id}: {name}"))
                } else {
                    st.profiles.replace_outbound(id as u32, outbound).map_err(|e| anyhow::anyhow!("{e}"))?;
                    st.save_profiles()?;
                    Ok(format!("已保存节点 #{id}"))
                }
            })();
            match msg {
                Ok(s) => {
                    w.set_log_text(SharedString::from(s));
                    w.set_node_editor_open(false);
                    rebuild_profiles(&w, &state::lock(&state));
                }
                Err(e) => w.set_node_editor_error(SharedString::from(e.to_string())),
            }
        });
    }
}

/// Connections view (Phase 5): filter/search hook + close-one/close-all.
fn wire_connections_callbacks(win: &MainWindow, paths: &Paths) {
    {
        let w = win.as_weak();
        win.on_connections_filter_changed(move || {
            // the status timer already fetches connections() every 1.5s and rebuilds
            // connections-rows from the current search/filter properties on each tick —
            // nothing to recompute immediately here, this just exists so the .slint side
            // has a callback to hook onto LineEdit `edited`/chip clicks.
            let _ = w.upgrade();
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        win.on_close_connection(move |id| {
            let Some(w) = w.upgrade() else { return };
            match guderray_engine::close_connection(&paths, &id) {
                Ok(_) => w.set_log_text(SharedString::from(format!("已断开连接 {id}"))),
                Err(e) => w.set_log_text(SharedString::from(format!("断开失败: {e}"))),
            }
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        win.on_close_all_connections(move || {
            let Some(w) = w.upgrade() else { return };
            match guderray_engine::close_all_connections(&paths) {
                Ok(_) => w.set_log_text(SharedString::from("已断开全部连接")),
                Err(e) => w.set_log_text(SharedString::from(format!("断开失败: {e}"))),
            }
        });
    }
}

/// Rules view (Phase 6): chip add/remove (immediate persistence, no separate Save step),
/// the 3-way routing-mode selector, and the live preview classifier.
fn wire_rules_callbacks(win: &MainWindow, state: &SharedState) {
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_rule_add(move |bucket, entry| {
            let entry = entry.trim().to_string();
            if entry.is_empty() {
                return;
            }
            let mut st = state::lock(&state);
            let list = match bucket.as_str() {
                "direct" => &mut st.settings.user_rules.direct,
                "proxy" => &mut st.settings.user_rules.proxy,
                "block" => &mut st.settings.user_rules.block,
                _ => return,
            };
            let mut lines = list.to_lines();
            if !lines.is_empty() {
                lines.push('\n');
            }
            lines.push_str(&entry);
            *list = guderray_core::RuleList::from_lines(&lines);
            let _ = st.save_settings();
            if let Some(w) = w.upgrade() {
                refresh_rules_view(&w, &st);
            }
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_rule_remove(move |bucket, entry| {
            let mut st = state::lock(&state);
            let list = match bucket.as_str() {
                "direct" => &mut st.settings.user_rules.direct,
                "proxy" => &mut st.settings.user_rules.proxy,
                "block" => &mut st.settings.user_rules.block,
                _ => return,
            };
            let remaining: String =
                list.to_lines().lines().filter(|l| *l != entry.as_str()).collect::<Vec<_>>().join("\n");
            *list = guderray_core::RuleList::from_lines(&remaining);
            let _ = st.save_settings();
            if let Some(w) = w.upgrade() {
                refresh_rules_view(&w, &st);
            }
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_set_routing_mode(move |mode| {
            let mut st = state::lock(&state);
            st.settings.routing = match mode.as_str() {
                "global" => RoutingMode::Global,
                "custom" => RoutingMode::Custom,
                _ => RoutingMode::CnDirect,
            };
            let _ = st.save_settings();
            if let Some(w) = w.upgrade() {
                // keep the Dashboard's boolean China-Direct toggle in sync — it can only
                // represent Global/CnDirect, so Custom mode shows it as "off".
                w.set_cn_direct(st.settings.routing == RoutingMode::CnDirect);
                refresh_rules_view(&w, &st);
            }
        });
    }
    {
        let state = state.clone();
        win.on_preview_classify(move |domain| {
            let st = state::lock(&state);
            SharedString::from(guderray_core::classify_domain(&st.settings.user_rules, st.settings.routing, &domain))
        });
    }
}

/// Routing/TUN/system-proxy toggles + core asset download.
fn wire_routing_callbacks(win: &MainWindow, paths: &Paths, state: &SharedState) {
    {
        let state = state.clone();
        win.on_toggle_cn(move |on| {
            let mut st = state::lock(&state);
            st.settings.routing = if on { RoutingMode::CnDirect } else { RoutingMode::Global };
            let _ = st.save_settings();
        });
    }
    {
        let state = state.clone();
        win.on_toggle_tun(move |on| {
            let mut st = state::lock(&state);
            st.settings.tun = on;
            let _ = st.save_settings();
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        let state = state.clone();
        win.on_toggle_sysproxy(move |on| {
            let msg = match guderray_engine::set_sysproxy(&paths, on) {
                Ok(v) => {
                    // set_sysproxy is engine-layer and already persisted this field;
                    // mirror it into the cache so it doesn't go stale.
                    state::lock(&state).settings.system_proxy = on;
                    pretty(&v)
                }
                Err(e) => format!("系统代理切换失败: {e}"),
            };
            if let Some(w) = w.upgrade() {
                w.set_log_text(SharedString::from(msg));
            }
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        let state = state.clone();
        win.on_sync_assets(move || {
            let Some(w) = w.upgrade() else { return };
            if w.get_assets_syncing() {
                return;
            }
            w.set_assets_syncing(true);
            w.set_log_text(SharedString::from(
                "正在下载核心组件 (sing-box / wintun / 中国直连规则集)…",
            ));
            let w_weak = w.as_weak();
            let paths = paths.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                let result = guderray_engine::assets::sync(&paths, None);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(w) = w_weak.upgrade() else { return };
                    w.set_assets_syncing(false);
                    match result {
                        Ok(v) => {
                            w.set_log_text(SharedString::from(format!(
                                "核心组件下载完成:\n{}",
                                pretty(&v)
                            )));
                            let st = state::lock(&state);
                            w.set_assets_ready(
                                guderray_engine::resolve_singbox(&st.paths, &st.settings).is_ok(),
                            );
                            w.set_ruleset_updated_text(SharedString::from(ruleset_updated_text(
                                &st.paths,
                            )));
                        }
                        Err(e) => {
                            w.set_log_text(SharedString::from(format!("下载失败: {e}")));
                        }
                    }
                });
            });
        });
    }
}

/// Settings view: routing rules, subscriptions, autostart/autoconnect, theme, language.
fn wire_settings_callbacks(win: &MainWindow, paths: &Paths, state: &SharedState) {
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_open_settings(move || {
            if let Some(w) = w.upgrade() {
                let st = state::lock(&state);
                load_settings_view(&w, &st);
                refresh_advanced_settings(&w, &st);
            }
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_save_advanced_settings(move || {
            let Some(w) = w.upgrade() else { return };
            let msg = (|| -> anyhow::Result<()> {
                let mut st = state::lock(&state);
                st.settings.socks_port = w.get_settings_socks_port().clamp(1, u16::MAX as i32) as u16;
                st.settings.socks_listen = w.get_settings_socks_listen().to_string();
                st.settings.clash_api_port = w.get_settings_clash_api_port().clamp(1, u16::MAX as i32) as u16;
                st.settings.direct_dns = w.get_settings_direct_dns().to_string();
                st.settings.remote_dns = w.get_settings_remote_dns().to_string();
                st.settings.dns_strategy = w.get_settings_dns_strategy().to_string();
                st.settings.tun_stack = w.get_settings_tun_stack().to_string();
                st.settings.tun_mtu = w.get_settings_tun_mtu().clamp(576, u32::MAX as i32) as u32;
                st.settings.tun_strict_route = w.get_settings_tun_strict_route();
                st.settings.log_level = w.get_settings_log_level().to_string();
                st.settings.block_ads = w.get_settings_block_ads();
                st.save_settings()?;
                Ok(())
            })();
            w.set_log_text(SharedString::from(match msg {
                Ok(_) => "高级设置已保存（下次启动代理时生效）。".to_string(),
                Err(e) => format!("保存高级设置失败: {e}"),
            }));
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        let state = state.clone();
        win.on_sub_add(move |name, url| {
            let name = name.trim().to_string();
            let url = url.trim().to_string();
            if name.is_empty() || url.is_empty() {
                if let Some(w) = w.upgrade() {
                    w.set_log_text(SharedString::from("请填写订阅名称和链接。"));
                }
                return;
            }
            if let Some(w) = w.upgrade() {
                w.set_log_text(SharedString::from(format!("正在拉取订阅「{name}」…")));
            }
            let w2 = w.clone();
            let paths = paths.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                // sub_add is engine-layer: it persists both SubStore and ProfileStore
                // itself, so the cache is reloaded rather than written through here.
                let r = guderray_engine::sub_add(&paths, &name, &url);
                let state2 = state.clone();
                let _ = w2.upgrade_in_event_loop(move |win| {
                    win.set_log_text(SharedString::from(match &r {
                        Ok(v) => format!("订阅已更新:\n{}", pretty(v)),
                        Err(e) => format!("订阅拉取失败: {e}"),
                    }));
                    let _ = state::lock(&state2).reload();
                    let st = state::lock(&state2);
                    load_settings_view(&win, &st);
                    rebuild_profiles(&win, &st);
                });
            });
        });
    }
    {
        let w = win.as_weak();
        let paths = paths.clone();
        let state = state.clone();
        win.on_sub_update_all(move || {
            if let Some(w) = w.upgrade() {
                w.set_log_text(SharedString::from("正在更新全部订阅…"));
            }
            let w2 = w.clone();
            let paths = paths.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                let r = guderray_engine::sub_update(&paths, None);
                let state2 = state.clone();
                let _ = w2.upgrade_in_event_loop(move |win| {
                    win.set_log_text(SharedString::from(match &r {
                        Ok(v) => format!("订阅更新完成:\n{}", pretty(v)),
                        Err(e) => format!("订阅更新失败: {e}"),
                    }));
                    let _ = state::lock(&state2).reload();
                    let st = state::lock(&state2);
                    load_settings_view(&win, &st);
                    rebuild_profiles(&win, &st);
                });
            });
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_sub_remove(move |name| {
            let mut st = state::lock(&state);
            st.subs.remove(&name);
            let _ = st.save_subs();
            if let Some(w) = w.upgrade() {
                w.set_log_text(SharedString::from(format!("已删除订阅「{name}」（保留已导入节点）。")));
                load_settings_view(&w, &st);
            }
        });
    }
    {
        let w = win.as_weak();
        win.on_toggle_autostart(move |on| {
            let msg = match guderray_engine::set_autostart(on) {
                Ok(_) => format!("开机自启已{}", if on { "开启" } else { "关闭" }),
                Err(e) => format!("设置开机自启失败: {e}"),
            };
            if let Some(w) = w.upgrade() {
                w.set_log_text(SharedString::from(msg));
                w.set_autostart(guderray_engine::get_autostart());
            }
        });
    }
    {
        let state = state.clone();
        win.on_toggle_autoconnect(move |on| {
            let mut st = state::lock(&state);
            st.settings.auto_connect = on;
            let _ = st.save_settings();
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_toggle_dark_mode(move || {
            if let Some(w) = w.upgrade() {
                let mut st = state::lock(&state);
                st.settings.ui_dark_mode = w.get_dark_mode();
                let _ = st.save_settings();
            }
        });
    }
    {
        let w = win.as_weak();
        let state = state.clone();
        win.on_toggle_language(move || {
            if let Some(w) = w.upgrade() {
                let new_lang = {
                    let mut st = state::lock(&state);
                    st.settings.language = if st.settings.language == "en" { "zh".into() } else { "en".into() };
                    let _ = st.save_settings();
                    st.settings.language.clone()
                };
                apply_language(&w, &new_lang);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Timers — also extracted out of `main()` for the same reason as the callbacks above;
// the status timer's closure in particular was the single largest chunk of code
// (~150 lines of deeply nested logic) contributing to the MIR-building crash.
// ---------------------------------------------------------------------------

/// One status-timer tick: refresh running/uptime/session state, the traffic chart
/// history, and every Connections-view/Dashboard-preview property. Runs every 1.5s.
#[allow(clippy::too_many_arguments)]
fn poll_status_tick(
    w: &MainWindow,
    paths: &Paths,
    state: &SharedState,
    last: &Rc<RefCell<Option<(u64, u64, Instant)>>>,
    was_running: &Rc<RefCell<bool>>,
    history: &Rc<RefCell<VecDeque<(f64, f64)>>>,
    session_start: &Rc<RefCell<Option<Instant>>>,
    history_cap: usize,
) {
    let before = *was_running.borrow();
    apply_status(w, paths);
    if w.get_live_log() {
        w.set_log_text(SharedString::from(tail_log(paths, 60)));
    }
    let now_running = w.get_is_running();
    if before && !now_running {
        // read straight from the in-memory cache — no disk I/O on every tick.
        let (auto_restart, last_id) = {
            let st = state::lock(state);
            (st.settings.auto_restart, st.settings.last_profile_id)
        };
        if auto_restart {
            if let Some(id) = last_id {
                w.set_log_text(SharedString::from("检测到核心进程退出，正在自动重连..."));
                let _ = guderray_engine::up(paths, id, None, None);
                apply_status(w, paths);
            }
        } else {
            w.set_log_text(SharedString::from("检测到核心进程已退出。"));
        }
    }
    *was_running.borrow_mut() = w.get_is_running();
    if !w.get_is_running() {
        *last.borrow_mut() = None;
        *session_start.borrow_mut() = None;
        history.borrow_mut().clear();
        w.set_speed_text(SharedString::from(""));
        w.set_uptime_text(SharedString::from(""));
        w.set_session_text(SharedString::from(""));
        w.set_chart_down_fill(SharedString::from(""));
        w.set_chart_down_stroke(SharedString::from(""));
        w.set_chart_up_stroke(SharedString::from(""));
        w.set_chart_has_data(false);
        w.set_active_connections(0);
        w.set_recent_connections(ModelRc::new(VecModel::from(Vec::<ConnDisplayRow>::new())));
        return;
    }
    let start = *session_start.borrow_mut().get_or_insert_with(Instant::now);
    w.set_uptime_text(SharedString::from(fmt_uptime(start.elapsed())));
    if let Ok(v) = guderray_engine::stats(paths) {
        let down = v["download_total"].as_u64().unwrap_or(0);
        let up = v["upload_total"].as_u64().unwrap_or(0);
        w.set_session_text(SharedString::from(fmt_bytes(down + up)));
        let now = Instant::now();
        let mut prev = last.borrow_mut();
        if let Some((pd, pu, pt)) = *prev {
            let secs = now.duration_since(pt).as_secs_f64().max(0.001);
            let d_rate = down.saturating_sub(pd) as f64 / secs;
            let u_rate = up.saturating_sub(pu) as f64 / secs;
            w.set_speed_text(SharedString::from(format!(
                "↓ {}  ↑ {}",
                fmt_rate(d_rate),
                fmt_rate(u_rate)
            )));

            let mut hist = history.borrow_mut();
            hist.push_back((d_rate, u_rate));
            while hist.len() > history_cap {
                hist.pop_front();
            }
            let (fill, down_stroke, up_stroke, has_data) = build_chart_paths(&hist);
            w.set_chart_down_fill(SharedString::from(fill));
            w.set_chart_down_stroke(SharedString::from(down_stroke));
            w.set_chart_up_stroke(SharedString::from(up_stroke));
            w.set_chart_has_data(has_data);
        }
        *prev = Some((down, up, now));
    }
    match guderray_engine::connections(paths) {
        Ok(v) => {
            let rows = map_connections(&v);
            w.set_active_connections(rows.len() as i32);
            let preview: Vec<ConnDisplayRow> = rows
                .iter()
                .take(5)
                .map(|c| ConnDisplayRow {
                    host: SharedString::from(c.host.clone()),
                    destination: SharedString::from(c.destination.clone()),
                    down_text: SharedString::from(fmt_bytes(c.download)),
                    up_text: SharedString::from(fmt_bytes(c.upload)),
                })
                .collect();
            w.set_recent_connections(ModelRc::new(VecModel::from(preview)));

            // Connections view (Phase 5): classify every row, tally counts from
            // the FULL unfiltered set (so the filter chips show true totals), then
            // apply the current search/route-filter for the table itself.
            let mut counts = (0i32, 0i32, 0i32); // (direct, proxy, block)
            let classified: Vec<(connections::ConnRow, &'static str)> = rows
                .into_iter()
                .map(|c| {
                    let route = guderray_core::classify_connection(&c.rule, &c.chains);
                    match route {
                        "direct" => counts.0 += 1,
                        "block" => counts.2 += 1,
                        _ => counts.1 += 1,
                    }
                    (c, route)
                })
                .collect();
            w.set_connections_count_all(classified.len() as i32);
            w.set_connections_count_direct(counts.0);
            w.set_connections_count_proxy(counts.1);
            w.set_connections_count_block(counts.2);

            let search = w.get_connections_search().to_string().to_lowercase();
            let filter = w.get_connections_filter().to_string();
            let view_rows: Vec<ConnectionRow> = classified
                .into_iter()
                .filter(|(c, route)| {
                    (filter.is_empty() || filter == *route)
                        && (search.is_empty() || c.host.to_lowercase().contains(&search))
                })
                .map(|(c, route)| ConnectionRow {
                    id: SharedString::from(c.id),
                    host: SharedString::from(if c.host.is_empty() { c.destination.clone() } else { c.host }),
                    destination: SharedString::from(c.destination),
                    route: SharedString::from(route),
                    duration: SharedString::from(connections::elapsed_since(&c.start)),
                    down_text: SharedString::from(fmt_bytes(c.download)),
                    up_text: SharedString::from(fmt_bytes(c.upload)),
                })
                .collect();
            w.set_connections_rows(ModelRc::new(VecModel::from(view_rows)));
        }
        Err(_) => {
            w.set_active_connections(0);
            w.set_recent_connections(ModelRc::new(VecModel::from(Vec::<ConnDisplayRow>::new())));
            w.set_connections_rows(ModelRc::new(VecModel::from(Vec::<ConnectionRow>::new())));
            w.set_connections_count_all(0);
            w.set_connections_count_direct(0);
            w.set_connections_count_proxy(0);
            w.set_connections_count_block(0);
        }
    }
}

/// Starts the 1.5s status-poll timer. Returns the `Timer` — the caller must keep it
/// alive (a dropped `Timer` stops firing) for as long as the app runs.
fn start_status_timer(win: &MainWindow, paths: &Paths, state: &SharedState) -> Timer {
    let timer = Timer::default();
    let w = win.as_weak();
    let paths = paths.clone();
    let state = state.clone();
    // (down_total, up_total, at)
    let last: Rc<RefCell<Option<(u64, u64, Instant)>>> = Rc::new(RefCell::new(None));
    let was_running: Rc<RefCell<bool>> = Rc::new(RefCell::new(false));
    // rolling ~60-sample (~90s) (download_rate, upload_rate) history for the
    // oscilloscope-style traffic chart; cleared whenever the core stops so the
    // chart never shows a stale/frozen trace from a previous session.
    let history: Rc<RefCell<VecDeque<(f64, f64)>>> = Rc::new(RefCell::new(VecDeque::new()));
    let session_start: Rc<RefCell<Option<Instant>>> = Rc::new(RefCell::new(None));
    const HISTORY_CAP: usize = 60;
    timer.start(TimerMode::Repeated, Duration::from_millis(1500), move || {
        let Some(w) = w.upgrade() else { return };
        poll_status_tick(&w, &paths, &state, &last, &was_running, &history, &session_start, HISTORY_CAP);
    });
    timer
}

/// Starts the 120ms tray/menu event pump. Returns the `Timer` — the caller must keep
/// it alive for as long as the app runs.
fn start_tray_timer(
    win: &MainWindow,
    paths: &Paths,
    id_show: MenuId,
    id_stop: MenuId,
    id_quit: MenuId,
) -> Timer {
    let tray_timer = Timer::default();
    let w = win.as_weak();
    let paths = paths.clone();
    let menu_rx = MenuEvent::receiver();
    let tray_rx = TrayIconEvent::receiver();
    tray_timer.start(TimerMode::Repeated, Duration::from_millis(120), move || {
        while let Ok(ev) = tray_rx.try_recv() {
            if let TrayIconEvent::Click { button: tray_icon::MouseButton::Left, .. } = ev {
                if let Some(w) = w.upgrade() {
                    let _ = w.show();
                }
            }
        }
        while let Ok(ev) = menu_rx.try_recv() {
            if ev.id == id_show {
                if let Some(w) = w.upgrade() {
                    let _ = w.show();
                }
            } else if ev.id == id_stop {
                let _ = guderray_engine::down(&paths);
                if let Some(w) = w.upgrade() {
                    apply_status(&w, &paths);
                }
            } else if ev.id == id_quit {
                let _ = guderray_engine::down(&paths);
                let _ = slint::quit_event_loop();
            }
        }
    });
    tray_timer
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths = Paths::discover();
    let _ = paths.ensure();
    let _ = guderray_engine::reconcile(&paths);

    let state: SharedState = Arc::new(Mutex::new(AppState::load(paths.clone())?));

    let win = MainWindow::new()?;
    win.set_app_icon(slint_icon());

    // ---- system tray ----
    let tray_menu = Menu::new();
    let mi_show = MenuItem::new("显示主界面", true, None);
    let mi_stop = MenuItem::new("停止代理", true, None);
    let mi_quit = MenuItem::new("退出", true, None);
    let _ = tray_menu.append(&mi_show);
    let _ = tray_menu.append(&PredefinedMenuItem::separator());
    let _ = tray_menu.append(&mi_stop);
    let _ = tray_menu.append(&PredefinedMenuItem::separator());
    let _ = tray_menu.append(&mi_quit);
    let (irgba, iw, ih) = icon::rgba();
    let tray_img = tray_icon::Icon::from_rgba(irgba, iw, ih)
        .unwrap_or_else(|_| tray_icon::Icon::from_rgba(vec![59, 130, 246, 255], 1, 1).unwrap());
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("GuderRay")
        .with_icon(tray_img)
        .build()
        .ok();
    let id_show = mi_show.id().clone();
    let id_stop = mi_stop.id().clone();
    let id_quit = mi_quit.id().clone();

    // close button → hide to tray instead of quitting
    {
        let w = win.as_weak();
        win.window().on_close_requested(move || {
            if let Some(w) = w.upgrade() {
                let _ = w.hide();
            }
            CloseRequestResponse::HideWindow
        });
    }

    // ---- initial state from the freshly-loaded cache ----
    let auto_connect_target = {
        let st = state::lock(&state);
        win.set_cn_direct(st.settings.routing == RoutingMode::CnDirect);
        win.set_tun(st.settings.tun);
        win.set_sysproxy(st.settings.system_proxy);
        win.set_dark_mode(st.settings.ui_dark_mode);
        win.invoke_apply_theme(st.settings.ui_dark_mode);
        apply_language(&win, &st.settings.language);
        win.set_autostart_supported(cfg!(windows));
        win.set_assets_ready(guderray_engine::resolve_singbox(&st.paths, &st.settings).is_ok());
        win.set_autostart(guderray_engine::get_autostart());
        win.set_auto_connect(st.settings.auto_connect);
        if let Some(id) = st.settings.last_profile_id {
            win.set_selected_id(id as i32);
        }
        win.set_ruleset_updated_text(SharedString::from(ruleset_updated_text(&st.paths)));
        rebuild_profiles(&win, &st);
        refresh_rules_view(&win, &st);
        (st.settings.auto_connect && win.get_assets_ready() && !win.get_is_running())
            .then_some(st.settings.last_profile_id)
            .flatten()
    };
    apply_status(&win, &paths);

    // auto-connect the last profile on launch, if enabled and nothing is running yet
    if let Some(id) = auto_connect_target {
        let w = win.as_weak();
        let paths_ac = paths.clone();
        std::thread::spawn(move || {
            let r = guderray_engine::up(&paths_ac, id, None, None);
            let _ = w.upgrade_in_event_loop(move |win| {
                if let Err(e) = &r {
                    win.set_log_text(SharedString::from(format!("自动连接失败: {e}")));
                }
            });
        });
    }

    // ---- callbacks ----
    wire_profile_callbacks(&win, &paths, &state);
    wire_node_callbacks(&win, &state);
    wire_connections_callbacks(&win, &paths);
    wire_rules_callbacks(&win, &state);
    wire_routing_callbacks(&win, &paths, &state);
    wire_settings_callbacks(&win, &paths, &state);

    // ---- timers (kept alive for the app's lifetime) ----
    let _status_timer = start_status_timer(&win, &paths, &state);
    let _tray_timer = start_tray_timer(&win, &paths, id_show, id_stop, id_quit);

    win.run()?;
    Ok(())
}
