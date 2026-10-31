//! A real TUN and real routes in a throwaway network namespace, no sudo: the test re-executes itself under
//! `unshare -rn` (root only inside its own user and network namespace). The child brings the network up,
//! reports ready, takes SIGTERM through the blocked-signal path pqvpnd uses, and checks every route came back.
//! Without user namespaces it prints SKIP and passes.

use std::io::{BufRead, BufReader};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use pqvpnd::config::Ipv6Policy;
use pqvpnd::net::{Network, ipv6_preflight, killswitch_install, killswitch_present, run_ip};

const CHILD: &str = "PQVPND_NETNS_CHILD";

fn ip(args: &str) -> String {
    run_ip(&args.split_whitespace().map(str::to_owned).collect::<Vec<_>>(), true).unwrap_or_else(|e| panic!("{e}"))
}

fn routes() -> String {
    ip("route show table all")
}

fn nft_tables() -> String {
    let output = Command::new("nft").args(["list", "tables"]).output().expect("nft");
    assert!(output.status.success(), "nft list tables: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

/// Whether the host may send to `to`: a packet the kill switch drops fails the send with EPERM at once.
fn udp_allowed(from: &str, to: &str) -> bool {
    let socket = UdpSocket::bind(from).unwrap();
    match socket.send_to(b"probe", to) {
        Ok(_) => true,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => false,
        Err(error) => panic!("send {from} -> {to}: {error}"),
    }
}

/// Packets that fell through to the kill switch's final counter, i.e. were dropped.
fn kill_switch_drops() -> u64 {
    let output = Command::new("nft").args(["list", "chain", "inet", "pqvpn_killswitch", "output"]).output().expect("nft");
    let text = String::from_utf8(output.stdout).unwrap();
    let after = text.split("counter packets ").nth(1).unwrap_or_else(|| panic!("no counter in {text}"));
    after.split_whitespace().next().unwrap().parse().unwrap()
}

/// TCP does not fail fast on a dropped SYN, so judge it by the drop counter: unchanged means it went out.
fn tcp_allowed(to: &str) -> bool {
    let before = kill_switch_drops();
    let _ = TcpStream::connect_timeout(&to.parse::<SocketAddr>().unwrap(), Duration::from_millis(200));
    kill_switch_drops() == before
}

/// The K2 allow set, both phases, on a dummy uplink (server 192.0.2.1) and a dummy standing in for the TUN.
fn kill_switch_allow_set() {
    ip("link set lo up"); // a fresh namespace starts with loopback down
    ip("link add pqks0 type dummy");
    ip("addr add 10.8.0.2/24 dev pqks0");
    ip("link set pqks0 up");
    ip("-6 addr add 2001:db8::2/64 dev pqup0 nodad");
    let server = Ipv4Addr::new(192, 0, 2, 1);
    let open = |phase: &str| {
        assert!(udp_allowed("127.0.0.1:0", "127.0.0.1:9"), "{phase}: loopback");
        assert!(udp_allowed("0.0.0.0:68", "192.0.2.1:67"), "{phase}: DHCP");
        assert!(tcp_allowed("192.0.2.1:51820"), "{phase}: server control TCP");
    };
    killswitch_install(server, 51820, None).unwrap();
    assert!(killswitch_present().unwrap());
    open("connecting");
    for (to, what) in [("192.0.2.53:53", "DNS on the uplink"), ("192.0.2.1:51821", "data UDP before up"), ("10.8.0.1:53", "TUN before up")] {
        assert!(!udp_allowed("0.0.0.0:0", to), "connecting: {what} must be blocked");
    }
    // Replaced in place by the "up" phase, one transaction.
    killswitch_install(server, 51820, Some(("pqks0", 51821))).unwrap();
    open("up");
    assert!(udp_allowed("0.0.0.0:0", "192.0.2.1:51821"), "up: server data UDP");
    assert!(udp_allowed("0.0.0.0:0", "10.8.0.1:53"), "up: anything via the TUN, DNS included");
    assert!(!udp_allowed("0.0.0.0:0", "192.0.2.53:53"), "up: DNS on the uplink must be blocked");
    assert!(!udp_allowed("0.0.0.0:0", "192.0.2.1:51822"), "up: other server ports blocked");
    assert!(!tcp_allowed("192.0.2.1:22"), "up: server TCP other than control blocked");
    assert!(!udp_allowed("[::]:0", "[2001:db8::1]:53"), "up: IPv6 blocked");
    let recover = || {
        let output = Command::new(env!("CARGO_BIN_EXE_pqvpnd")).arg("recover").output().unwrap();
        assert!(output.status.success(), "recover: {}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap()
    };
    assert_eq!(recover(), "kill switch removed; traffic is no longer blocked\n");
    assert_eq!(recover(), "no kill switch was active\n", "idempotent");
    assert!(!killswitch_present().unwrap());
    assert!(udp_allowed("0.0.0.0:0", "192.0.2.53:53") && udp_allowed("[::]:0", "[2001:db8::1]:53"), "open again after remove");
    ip("-6 addr del 2001:db8::2/64 dev pqup0");
    ip("link del pqks0");
}

/// ipv6_policy = "fail" refuses while usable IPv6 exists, and a setup failure after the guard is up removes it.
fn ipv6_refusals() {
    ipv6_preflight(Ipv6Policy::Fail).expect("no IPv6 in a fresh namespace");
    ip("-6 addr add 2001:db8::2/64 dev pqup0 nodad");
    let error = ipv6_preflight(Ipv6Policy::Fail).unwrap_err();
    assert!(error.to_string().contains("ipv6_policy=fail"), "{error}");
    assert!(Network::up("pqfail0", Ipv4Addr::new(10, 8, 0, 2), 24, 1380, Ipv4Addr::new(192, 0, 2, 1), Ipv6Policy::Fail, &[]).is_err());
    assert!(run_ip(&["link".into(), "show".into(), "dev".into(), "pqfail0".into()], true).is_err(), "refused before leaving a TUN");
    ip("-6 addr del 2001:db8::2/64 dev pqup0");
    // No route to this server, so the bypass step fails after the guard went in: everything must be undone.
    let before = routes();
    assert!(Network::up("pqfail0", Ipv4Addr::new(10, 8, 0, 2), 24, 1380, Ipv4Addr::new(198, 51, 100, 1), Ipv6Policy::Block, &[]).is_err());
    assert!(!nft_tables().contains("pqvpn_client6_"), "guard removed after a failed setup");
    assert_eq!(routes(), before);
}

/// A stand-in for resolvectl that logs its argv (and fails on `fail_on`): the real one would talk to the HOST's
/// systemd-resolved over D-Bus, where this namespace's TUN index could name a host link.
fn stub_resolvectl(name: &str, fail_on: &str) -> (&'static str, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("netns-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (script, log) = (dir.join("resolvectl"), dir.join("log"));
    let _ = std::fs::remove_file(&log);
    std::fs::write(&script, format!("#!/bin/sh\necho \"$*\" >> '{}'\n[ \"$1\" != '{fail_on}' ]\n", log.display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (Box::leak(script.to_string_lossy().into_owned().into_boxed_str()), log)
}

fn log_of(log: &std::path::Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

/// DNS: nothing is run when unmanaged or without servers; a failing `domain` still reverts the link on rollback.
fn dns_rollback() {
    let (stub, log) = stub_resolvectl("fail", "domain");
    let mut network = Network::up("pqfail0", Ipv4Addr::new(10, 8, 0, 2), 24, 1380, Ipv4Addr::new(192, 0, 2, 1), Ipv6Policy::Allow, &[]).unwrap();
    network.dns(false, &["10.8.0.1".into()], &["~.".into()], || Ok(stub)).unwrap();
    network.dns(true, &[], &["~.".into()], || Ok(stub)).unwrap();
    assert_eq!(log_of(&log), "", "unmanaged or no servers: resolvectl never runs");
    assert!(network.dns(true, &["10.8.0.1".into()], &["~.".into()], || Ok(stub)).is_err());
    drop(network);
    assert_eq!(log_of(&log), "dns pqfail0 10.8.0.1\ndomain pqfail0 ~.\nrevert pqfail0\n", "registered before the first command");
}

/// A split route the kernel rejects after one went in: the first is undone and the route it replaced comes back.
fn split_route_rollback() {
    ip("route add 10.99.0.0/16 via 192.0.2.254 dev pqup0");
    let before = routes();
    let split = ["10.99.0.0/16".to_owned(), "10.98.0.0/33".to_owned()];
    assert!(Network::up("pqfail0", Ipv4Addr::new(10, 8, 0, 2), 24, 1380, Ipv4Addr::new(192, 0, 2, 1), Ipv6Policy::Allow, &split).is_err());
    assert_eq!(routes(), before, "partial split routes rolled back exactly");
    ip("route del 10.99.0.0/16 via 192.0.2.254 dev pqup0");
}

fn child() {
    let signals = pqvpnd::block_stop_signals().unwrap();
    // An uplink with a pre-existing host route to the "server", so the bypass route has something to restore.
    ip("link add pqup0 type dummy");
    ip("addr add 192.0.2.2/24 dev pqup0");
    ip("link set pqup0 up");
    ip("route add 192.0.2.1/32 dev pqup0 metric 77");
    ipv6_refusals();
    kill_switch_allow_set();
    split_route_rollback();
    dns_rollback();
    // A route the full tunnel replaces, so the restore has to put it back exactly.
    ip("route add 128.0.0.0/1 via 192.0.2.254 dev pqup0");
    let before = routes();

    let full = ["0.0.0.0/1".to_owned(), "128.0.0.0/1".to_owned()];
    let mut network = Network::up("pqtest0", Ipv4Addr::new(10, 8, 0, 2), 24, 1380, Ipv4Addr::new(192, 0, 2, 1), Ipv6Policy::Block, &full).unwrap();
    for half in full {
        assert!(ip(&format!("route show exact {half}")).trim().ends_with("dev pqtest0 scope link"), "{half} via the TUN");
    }
    let table = network.ipv6_table.clone().expect("block installs the guard");
    assert!(nft_tables().contains(&format!("table ip6 {table}")), "IPv6 guard present while up");
    assert!(ip("-o addr show dev pqtest0").contains("10.8.0.2/24"), "TUN address");
    assert!(ip("-o link show dev pqtest0").contains("mtu 1380"), "TUN mtu");
    assert_eq!(std::fs::read_to_string("/proc/sys/net/ipv6/conf/pqtest0/disable_ipv6").unwrap().trim(), "1", "no IPv6 on the TUN");
    assert!(ip("route show exact 192.0.2.1/32").contains("dev pqup0"), "bypass route");
    assert_ne!(routes(), before, "routes changed while up");
    let (stub, log) = stub_resolvectl("main", "none");
    network.dns(true, &["10.8.0.1".into(), "10.8.0.53".into()], &["~.".into()], || Ok(stub)).unwrap();
    assert_eq!(log_of(&log), "dns pqtest0 10.8.0.1 10.8.0.53\ndomain pqtest0 ~.\n");
    println!("ready");

    let signal = pqvpnd::wait_for_stop(&signals).unwrap();
    drop(network);
    assert_eq!(routes(), before, "every route restored after {signal:?}");
    assert!(log_of(&log).ends_with("domain pqtest0 ~.\nrevert pqtest0\n"), "DNS reverted after {signal:?}");
    assert!(!nft_tables().contains("pqvpn_client6_"), "IPv6 guard removed after {signal:?}");
    assert!(run_ip(&["link".into(), "show".into(), "dev".into(), "pqtest0".into()], true).is_err(), "TUN closed and gone");
    println!("restored after {signal:?}");
}

fn main() {
    if std::env::var_os(CHILD).is_some() {
        child();
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let spawned = Command::new("unshare").args(["-rn"]).arg(&exe).env(CHILD, "1")
        .stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn();
    let mut process = match spawned {
        Ok(process) => process,
        Err(error) => {
            println!("SKIP netns: cannot run unshare -rn: {error}");
            return;
        }
    };
    let mut lines = BufReader::new(process.stdout.take().unwrap()).lines();
    let started = Instant::now();
    let first = lines.next().and_then(Result::ok);
    if first.as_deref() != Some("ready") {
        let status = process.wait().unwrap();
        // unshare itself failing (no user namespaces) exits before printing anything.
        if first.is_none() && started.elapsed() < Duration::from_secs(5) && status.code() == Some(1) {
            println!("SKIP netns: user namespaces unavailable");
            return;
        }
        panic!("child did not get ready: {first:?}, {status}");
    }
    // unshare execs the test binary, so this pid is the child itself.
    kill(Pid::from_raw(i32::try_from(process.id()).unwrap()), Signal::SIGTERM).unwrap();
    let last = lines.next().and_then(Result::ok);
    let status = process.wait().unwrap();
    assert!(status.success(), "child failed: {status}");
    assert_eq!(last.as_deref(), Some("restored after SIGTERM"));
    println!("netns: kill switch allow set, ipv6 fail/block refusals and rollback, split rollback, DNS rollback, full-tunnel routes and DNS, TUN up, bypass route, guard, SIGTERM cleanup restored everything: ok");
}
