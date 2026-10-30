//! TUN and routes for `pqvpnd connect`, mirroring `open_tun`/`configure_tun`/`ClientNetwork` in vpn/runtime.py:
//! `ip` is forked with an argv (never a shell), every route change records how to undo it, and `Network`
//! restores everything when it drops, whether the client exits normally, fails, or is told to stop by a signal.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Command, Stdio};

/// `ip` from a fixed location: pqvpnd runs as root, so it never resolves commands through PATH.
const IP_CANDIDATES: [&str; 4] = ["/usr/bin/ip", "/usr/sbin/ip", "/bin/ip", "/sbin/ip"];

fn ip_binary() -> io::Result<&'static str> {
    IP_CANDIDATES.into_iter().find(|path| Path::new(path).is_file())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ip(8) not found in /usr/bin, /usr/sbin, /bin or /sbin"))
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
}

impl Network {
    /// Opens the TUN, configures it, and routes the server's address around it. Any failure undoes the
    /// partial work before returning (the drop of `network`).
    pub fn up(tun_name: &str, address: Ipv4Addr, prefix: u8, mtu: u16, server: Ipv4Addr) -> io::Result<Self> {
        let (fd, name) = pqvpn_fd::open_tun(tun_name)?;
        let mut network = Network { tun: Some(fd), tun_name: name, undo: Vec::new() };
        // No IPv6 on the tunnel (pqvpnd refuses IPv6 policies), and no link-local chatter the server would drop.
        // Before link up; a kernel without IPv6 has no such file.
        match std::fs::write(format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", network.tun_name), "1") {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        run_ip(&addr_args(&network.tun_name, address, prefix), true)?;
        run_ip(&link_args(&network.tun_name, mtu), true)?;
        let route = run_ip(&argv(&["route", "get", &server.to_string()]), true)?;
        let (via, dev) = parse_route_get(&route)
            .ok_or_else(|| io::Error::other(format!("cannot parse `ip route get {server}`: {route:?}")))?;
        let destination = format!("{server}/32");
        network.replace_route(&destination, bypass_args(server, via.as_deref(), &dev))?;
        Ok(network)
    }

    fn replace_route(&mut self, destination: &str, route: Vec<String>) -> io::Result<()> {
        let previous = parse_routes(&run_ip(&argv(&["route", "show", "exact", destination]), true)?);
        run_ip(&[argv(&["route", "replace"]), route.clone()].concat(), true)?;
        self.undo.push(RouteUndo { installed: route, previous });
        Ok(())
    }

    /// Best effort and idempotent: undo routes newest first, then close the TUN (which removes its address).
    pub fn restore(&mut self) {
        while let Some(undo) = self.undo.pop() {
            for command in undo.commands() {
                let _ = run_ip(&command, false);
            }
        }
        self.tun.take();
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
