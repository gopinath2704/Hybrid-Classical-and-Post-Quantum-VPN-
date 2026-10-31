//! TUN and routes for `pqvpnd connect`, mirroring `open_tun`/`configure_tun`/`ClientNetwork` in vpn/runtime.py:
//! `ip` is forked with an argv (never a shell), every route change records how to undo it, and `Network`
//! restores everything when it drops, whether the client exits normally, fails, or is told to stop by a signal.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::config::Ipv6Policy;

/// `ip` from a fixed location: pqvpnd runs as root, so it never resolves commands through PATH.
const IP_CANDIDATES: [&str; 4] = ["/usr/bin/ip", "/usr/sbin/ip", "/bin/ip", "/sbin/ip"];

const RESOLVECTL_CANDIDATES: [&str; 4] = ["/usr/bin/resolvectl", "/usr/sbin/resolvectl", "/bin/resolvectl", "/sbin/resolvectl"];

/// `resolvectl` from a fixed location, with Python's message when it is missing.
pub fn resolvectl_binary() -> io::Result<&'static str> {
    binary(RESOLVECTL_CANDIDATES, "resolvectl").map_err(|_| io::Error::new(io::ErrorKind::NotFound,
        "configured VPN DNS requires resolvectl; use dns_mode=none only to explicitly accept unmanaged DNS"))
}

/// Runs `program ARGS` (argv, no shell); a non-zero exit is an error carrying its stderr.
fn run_checked(program: &str, args: &[&str]) -> io::Result<()> {
    let output = Command::new(program).args(args).stdin(Stdio::null()).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim())));
    }
    Ok(())
}

const NFT_CANDIDATES: [&str; 4] = ["/usr/bin/nft", "/usr/sbin/nft", "/bin/nft", "/sbin/nft"];

fn binary(candidates: [&'static str; 4], name: &str) -> io::Result<&'static str> {
    candidates.into_iter().find(|path| Path::new(path).is_file())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not found in /usr/bin, /usr/sbin, /bin or /sbin")))
}

fn ip_binary() -> io::Result<&'static str> {
    binary(IP_CANDIDATES, "ip(8)")
}

/// Runs `nft ARGS`, feeding `input` on stdin (`nft -f -`); a non-zero exit is an error carrying nft's stderr.
fn run_nft(args: &[&str], input: Option<&str>) -> io::Result<()> {
    let mut child = Command::new(binary(NFT_CANDIDATES, "nft(8)")?).args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::null()).stderr(Stdio::piped()).spawn()?;
    if let Some(text) = input {
        child.stdin.take().expect("piped").write_all(text.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("nft {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim())));
    }
    Ok(())
}

/// `IPv6Guard.apply`'s batch, byte for byte: a table of our own (created, never replaced) that drops every IPv6
/// packet this host sends except over loopback, and forwards none.
pub fn ipv6_guard_rules(table: &str) -> String {
    format!("create table ip6 {table}\n\
             add chain ip6 {table} output {{ type filter hook output priority filter; policy accept; }}\n\
             add rule ip6 {table} output oifname \"lo\" accept\n\
             add rule ip6 {table} output counter drop\n\
             add chain ip6 {table} forward {{ type filter hook forward priority filter; policy drop; }}\n")
}

/// `connectivity`: the usable IPv6 routes and addresses in `ip -j -6 route show table all` and `ip -j -6 addr
/// show` output. Conservative, not a reachability probe; ULA counts as usable.
pub fn ipv6_connectivity(routes: &str, addresses: &str) -> io::Result<Vec<String>> {
    let parse = |text: &str| serde_json::from_str::<Vec<serde_json::Value>>(text).map_err(io::Error::other);
    let text = |value: &serde_json::Value, key: &str| value.get(key).and_then(serde_json::Value::as_str).map(str::to_owned);
    let mut found = Vec::new();
    for route in parse(routes)? {
        if text(&route, "type").as_deref().unwrap_or("unicast") != "unicast" || text(&route, "dev").as_deref() == Some("lo") {
            continue;
        }
        let dst = text(&route, "dst").unwrap_or_else(|| "default".into());
        let (address, prefix) = if dst == "default" { ("::", "0") } else { dst.split_once('/').unwrap_or((dst.as_str(), "128")) };
        let address: Ipv6Addr = address.parse().map_err(|_| io::Error::other(format!("unparsable IPv6 route {dst:?}")))?;
        let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 128).ok_or_else(|| io::Error::other(format!("unparsable IPv6 route {dst:?}")))?;
        // ipaddress's network-level is_link_local / is_multicast: the whole network inside fe80::/10 or ff00::/8.
        let segment = address.segments()[0];
        let link_local = prefix >= 10 && segment & 0xffc0 == 0xfe80;
        let multicast = prefix >= 8 && segment & 0xff00 == 0xff00;
        if !link_local && !multicast {
            found.push(format!("route {dst} dev {}", text(&route, "dev").unwrap_or_else(|| "?".into())));
        }
    }
    for interface in parse(addresses)? {
        for address in interface.get("addr_info").and_then(serde_json::Value::as_array).into_iter().flatten() {
            let flags: Vec<&str> = address.get("flags").and_then(serde_json::Value::as_array).into_iter().flatten()
                .filter_map(serde_json::Value::as_str).collect();
            let set = |key: &str| address.get(key).is_some_and(|v| v.as_bool().unwrap_or(!v.is_null()));
            if text(address, "scope").as_deref() == Some("global") && !flags.iter().any(|f| matches!(*f, "tentative" | "dadfailed"))
                && !set("tentative") && !set("dadfailed") {
                found.push(format!("address {} on {}", text(address, "local").unwrap_or_default(),
                                   text(&interface, "ifname").unwrap_or_default()));
            }
        }
    }
    Ok(found)
}

pub const KILL_SWITCH_TABLE: &str = "pqvpn_killswitch";

/// `killswitch_rules`: the whole table in one transaction (destroy and re-add commit together, so a replace has
/// no gap). `up = None` is the "connecting" phase: loopback, DHCP and the server's control TCP only; `Some((tun,
/// udp_port))` adds the server's data UDP and the TUN. Held to tests/golden/killswitch_*.nft, like the Python side.
pub fn killswitch_rules(server: Ipv4Addr, control_port: u16, up: Option<(&str, u16)>) -> String {
    let t = format!("inet {KILL_SWITCH_TABLE}");
    let mut rules = vec![
        format!("destroy table {t}"),
        format!("add table {t}"),
        format!("add chain {t} output {{ type filter hook output priority filter; policy drop; }}"),
        format!("add rule {t} output oifname \"lo\" accept"),
        format!("add rule {t} output udp sport 68 udp dport 67 accept"),
        format!("add rule {t} output ip daddr {server} tcp dport {control_port} accept"),
    ];
    if let Some((tun, udp_port)) = up {
        rules.push(format!("add rule {t} output ip daddr {server} udp dport {udp_port} accept"));
        rules.push(format!("add rule {t} output oifname \"{tun}\" accept"));
    }
    rules.push(format!("add rule {t} output counter"));
    rules.join("\n") + "\n"
}

/// The table outlives this process on purpose: a crash leaves traffic blocked. Only disconnect or recover removes it.
pub fn killswitch_install(server: Ipv4Addr, control_port: u16, up: Option<(&str, u16)>) -> io::Result<()> {
    run_nft(&["-f", "-"], Some(&killswitch_rules(server, control_port, up)))
}

pub fn killswitch_present() -> io::Result<bool> {
    Ok(Command::new(binary(NFT_CANDIDATES, "nft(8)")?).args(["list", "table", "inet", KILL_SWITCH_TABLE])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status()?.success())
}

pub fn killswitch_remove() -> io::Result<()> {
    run_nft(&["destroy", "table", "inet", KILL_SWITCH_TABLE], None)
}

/// `preflight`: with policy "fail", refuse while any usable IPv6 exists.
pub fn ipv6_preflight(policy: Ipv6Policy) -> io::Result<()> {
    if policy != Ipv6Policy::Fail {
        return Ok(());
    }
    let routes = run_ip(&argv(&["-j", "-6", "route", "show", "table", "all"]), true)?;
    let addresses = run_ip(&argv(&["-j", "-6", "addr", "show"]), true)?;
    if ipv6_connectivity(&routes, &addresses)?.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other("IPv6 connectivity exists; ipv6_policy=fail refuses unsupported IPv6 bypass"))
    }
}

/// Runs `ip ARGS`; with `check`, a non-zero exit is an error carrying ip's stderr.
pub fn run_ip(args: &[String], check: bool) -> io::Result<String> {
    let output = Command::new(ip_binary()?).args(args).stdin(Stdio::null()).output()?;
    if check && !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!("ip {}: {}", args.join(" "), stderr.trim())));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// `configure_tun`: address, then MTU and link up.
pub fn addr_args(tun: &str, address: Ipv4Addr, prefix: u8) -> Vec<String> {
    argv(&["addr", "replace", &format!("{address}/{prefix}"), "dev", tun])
}

pub fn link_args(tun: &str, mtu: u16) -> Vec<String> {
    argv(&["link", "set", "dev", tun, "mtu", &mtu.to_string(), "up"])
}

/// The gateway and device from the first line of `ip route get SERVER`.
pub fn parse_route_get(output: &str) -> Option<(Option<String>, String)> {
    let words: Vec<&str> = output.lines().next()?.split_whitespace().collect();
    let after = |key: &str| words.iter().position(|w| *w == key).and_then(|i| words.get(i + 1)).map(|w| (*w).to_owned());
    Some((after("via"), after("dev")?))
}

/// The /32 route that keeps the tunnel's own traffic to the server off the tunnel.
pub fn bypass_args(server: Ipv4Addr, via: Option<&str>, dev: &str) -> Vec<String> {
    let mut args = argv(&[&format!("{server}/32")]);
    if let Some(gateway) = via {
        args.extend(argv(&["via", gateway]));
    }
    args.extend(argv(&["dev", dev]));
    args
}

/// `ip route show exact DEST`, one argv per route, as `shlex.split` would give for ip's unquoted output.
pub fn parse_routes(output: &str) -> Vec<Vec<String>> {
    output.lines().filter(|l| !l.trim().is_empty()).map(|l| l.split_whitespace().map(str::to_owned).collect()).collect()
}

/// `RouteUndo`: what was installed, and the exact routes it replaced.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteUndo {
    pub installed: Vec<String>,
    pub previous: Vec<Vec<String>>,
}

impl RouteUndo {
    /// The commands `_restore_ipv4_dns` runs for one undo: delete what we added, then put back what was there.
    pub fn commands(&self) -> Vec<Vec<String>> {
        let mut commands = vec![[argv(&["route", "del"]), self.installed.clone()].concat()];
        commands.extend(self.previous.iter().map(|route| [argv(&["route", "replace"]), route.clone()].concat()));
        commands
    }
}

/// The TUN and every route change, undone on drop.
pub struct Network {
    pub tun: Option<OwnedFd>,
    pub tun_name: String,
    undo: Vec<RouteUndo>,
    /// The `ip6` guard table we created, removed last.
    pub ipv6_table: Option<String>,
    /// The resolvectl that configured the TUN link's DNS, so restore can revert it first.
    dns_resolvectl: Option<String>,
}

impl Network {
    /// Opens the TUN, configures it, applies the IPv6 policy, routes the server's address around the TUN and then
    /// `routes` through it (`ClientNetwork.apply` order). Any failure undoes the partial work before returning (the
    /// drop of `network`).
    pub fn up(tun_name: &str, address: Ipv4Addr, prefix: u8, mtu: u16, server: Ipv4Addr, ipv6: Ipv6Policy, routes: &[String])
              -> io::Result<Self> {
        let (fd, name) = pqvpn_fd::open_tun(tun_name)?;
        let mut network = Network { tun: Some(fd), tun_name: name, undo: Vec::new(), ipv6_table: None, dns_resolvectl: None };
        // No IPv6 on the tunnel (pqvpnd refuses IPv6 policies), and no link-local chatter the server would drop.
        // Before link up; a kernel without IPv6 has no such file.
        match std::fs::write(format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", network.tun_name), "1") {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        run_ip(&addr_args(&network.tun_name, address, prefix), true)?;
        run_ip(&link_args(&network.tun_name, mtu), true)?;
        // `ClientNetwork.apply`: the IPv6 policy before any IPv4 route.
        match ipv6 {
            Ipv6Policy::Allow => eprintln!("pqvpnd: IPv6 bypass explicitly permitted or outside split-tunnel scope: IPv6 traffic is NOT protected by PQVPN"),
            Ipv6Policy::Fail => ipv6_preflight(ipv6)?,
            Ipv6Policy::Block => {
                let mut random = [0u8; 16];
                std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
                let table = format!("pqvpn_client6_{}", random.iter().map(|b| format!("{b:02x}")).collect::<String>());
                run_nft(&["-f", "-"], Some(&ipv6_guard_rules(&table)))?;
                network.ipv6_table = Some(table);
            }
        }
        let route = run_ip(&argv(&["route", "get", &server.to_string()]), true)?;
        let (via, dev) = parse_route_get(&route)
            .ok_or_else(|| io::Error::other(format!("cannot parse `ip route get {server}`: {route:?}")))?;
        let destination = format!("{server}/32");
        network.replace_route(&destination, bypass_args(server, via.as_deref(), &dev))?;
        for cidr in routes {
            network.replace_route(cidr, vec![cidr.clone(), "dev".into(), network.tun_name.clone()])?;
        }
        Ok(network)
    }

    /// The DNS step of `ClientNetwork.apply`: the TUN link's servers and routing domains through systemd-resolved.
    /// `resolvectl` is a parameter so the netns test can pass a stub: the real one would reach the host's resolved
    /// over D-Bus. Cleanup is registered before the first command, so a failure in either still reverts the link.
    pub fn dns(&mut self, manage: bool, servers: &[String], domains: &[String], resolvectl: impl FnOnce() -> io::Result<&'static str>)
               -> io::Result<()> {
        if !manage {
            eprintln!("pqvpnd: DNS is explicitly unmanaged (dns_mode=none); DNS may bypass the VPN");
            return Ok(());
        }
        if servers.is_empty() {
            return Ok(());
        }
        let program = resolvectl()?;
        self.dns_resolvectl = Some(program.to_owned());
        let tun = self.tun_name.clone();
        run_checked(program, &[["dns", tun.as_str()].as_slice(), &servers.iter().map(String::as_str).collect::<Vec<_>>()].concat())?;
        if !domains.is_empty() {
            run_checked(program, &[["domain", tun.as_str()].as_slice(), &domains.iter().map(String::as_str).collect::<Vec<_>>()].concat())?;
        }
        Ok(())
    }

    pub fn dns_managed(&self) -> bool {
        self.dns_resolvectl.is_some()
    }

    fn replace_route(&mut self, destination: &str, route: Vec<String>) -> io::Result<()> {
        let previous = parse_routes(&run_ip(&argv(&["route", "show", "exact", destination]), true)?);
        run_ip(&[argv(&["route", "replace"]), route.clone()].concat(), true)?;
        self.undo.push(RouteUndo { installed: route, previous });
        Ok(())
    }

    /// Best effort and idempotent: undo routes newest first, then close the TUN (which removes its address).
    pub fn restore(&mut self) {
        if let Some(program) = self.dns_resolvectl.take() {
            if let Err(error) = run_checked(&program, &["revert", &self.tun_name]) {
                eprintln!("pqvpnd: DNS revert failed for {}: {error}", self.tun_name);
            }
        }
        while let Some(undo) = self.undo.pop() {
            for command in undo.commands() {
                let _ = run_ip(&command, false);
            }
        }
        self.tun.take();
        // Last, as `ClientNetwork.restore` does; on failure keep the name so the leftover table is reported exactly.
        if let Some(table) = self.ipv6_table.take() {
            if let Err(error) = run_nft(&["delete", "table", "ip6", &table], None) {
                eprintln!("pqvpnd: IPv6 cleanup failed; owned table remains: ip6 {table}: {error}");
            }
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cleanup runs from `Drop`, which a panic only reaches while unwinding: panic = "abort" would leak routes and tables.
    #[test]
    fn workspace_keeps_panic_unwind() {
        assert!(!include_str!("../../Cargo.toml").contains("panic"), "core/Cargo.toml must not set a panic strategy");
    }

    #[test]
    fn killswitch_rules_match_the_python_golden_files() {
        let server = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(killswitch_rules(server, 51820, None), include_str!("../../../tests/golden/killswitch_connecting.nft"));
        assert_eq!(killswitch_rules(server, 51820, Some(("pqvpn0", 51821))), include_str!("../../../tests/golden/killswitch_up.nft"));
    }

    #[test]
    fn ipv6_guard_rules_match_ipv6guard() {
        assert_eq!(ipv6_guard_rules("pqvpn_client6_ab"), "create table ip6 pqvpn_client6_ab\n\
            add chain ip6 pqvpn_client6_ab output { type filter hook output priority filter; policy accept; }\n\
            add rule ip6 pqvpn_client6_ab output oifname \"lo\" accept\n\
            add rule ip6 pqvpn_client6_ab output counter drop\n\
            add chain ip6 pqvpn_client6_ab forward { type filter hook forward priority filter; policy drop; }\n");
    }

    /// The cases of test_read_only_connectivity_detection.
    #[test]
    fn ipv6_connectivity_matches_python() {
        let cases = [
            (r#"[{"dst":"default","dev":"eth0","gateway":"fe80::1"}]"#, "[]", true),
            ("[]", r#"[{"ifname":"eth0","addr_info":[{"scope":"global","local":"2001:db8::2"}]}]"#, true),
            (r#"[{"dst":"fe80::/64","dev":"eth0"}]"#, r#"[{"ifname":"lo","addr_info":[{"scope":"host","local":"::1"}]}]"#, false),
            (r#"[{"dst":"default","type":"unreachable"}]"#, "[]", false),
            ("[]", r#"[{"ifname":"eth0","addr_info":[{"scope":"global","local":"fd00::2"}]}]"#, true),
            (r#"[{"dst":"ff00::/8","dev":"eth0"},{"dst":"::1","dev":"lo"}]"#, "[]", false),
            ("[]", r#"[{"ifname":"eth0","addr_info":[{"scope":"global","local":"2001:db8::3","flags":["tentative"]}]}]"#, false),
            ("[]", r#"[{"ifname":"eth0","addr_info":[{"scope":"global","local":"2001:db8::4","dadfailed":true}]}]"#, false),
        ];
        for (routes, addresses, detected) in cases {
            assert_eq!(!ipv6_connectivity(routes, addresses).unwrap().is_empty(), detected, "{routes} {addresses}");
        }
        assert!(ipv6_connectivity(r#"[{"dst":"not-an-address","dev":"eth0"}]"#, "[]").is_err(), "unparsable fails closed");
    }

    #[test]
    fn argv_matches_the_python_client() {
        assert_eq!(addr_args("pqbench0", Ipv4Addr::new(10, 8, 0, 2), 24), ["addr", "replace", "10.8.0.2/24", "dev", "pqbench0"]);
        assert_eq!(link_args("pqbench0", 1380), ["link", "set", "dev", "pqbench0", "mtu", "1380", "up"]);
        let server = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(bypass_args(server, Some("192.168.1.1"), "wlan0"), ["192.0.2.1/32", "via", "192.168.1.1", "dev", "wlan0"]);
        assert_eq!(bypass_args(server, None, "bench-c"), ["192.0.2.1/32", "dev", "bench-c"]);
    }

    #[test]
    fn parses_ip_output() {
        let get = "192.0.2.1 via 192.168.1.1 dev wlan0 src 192.168.1.5 uid 1000 \n    cache \n";
        assert_eq!(parse_route_get(get), Some((Some("192.168.1.1".into()), "wlan0".into())));
        assert_eq!(parse_route_get("192.0.2.1 dev bench-c src 192.0.2.2 uid 0\n"), Some((None, "bench-c".into())));
        assert_eq!(parse_route_get("unreachable\n"), None);
        assert_eq!(parse_route_get(""), None);
        assert_eq!(parse_routes("192.0.2.1 dev eth0 metric 77 \n\n192.0.2.1 via 10.0.0.1 dev eth1\n"),
                   vec![vec!["192.0.2.1", "dev", "eth0", "metric", "77"], vec!["192.0.2.1", "via", "10.0.0.1", "dev", "eth1"]]);
    }

    #[test]
    fn undo_deletes_then_restores_previous_routes() {
        let undo = RouteUndo {
            installed: argv(&["192.0.2.1/32", "dev", "wlan0"]),
            previous: vec![argv(&["192.0.2.1", "dev", "eth0", "metric", "77"])],
        };
        assert_eq!(undo.commands(), vec![argv(&["route", "del", "192.0.2.1/32", "dev", "wlan0"]),
                                         argv(&["route", "replace", "192.0.2.1", "dev", "eth0", "metric", "77"])]);
    }
}
