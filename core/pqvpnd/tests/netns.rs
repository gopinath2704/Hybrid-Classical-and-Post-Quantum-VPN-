//! A real TUN and real routes in a throwaway network namespace, no sudo: the test re-executes itself under
//! `unshare -rn` (root only inside its own user and network namespace). The child brings the network up,
//! reports ready, takes SIGTERM through the blocked-signal path pqvpnd uses, and checks every route came back.
//! Without user namespaces it prints SKIP and passes.

use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use pqvpnd::config::Ipv6Policy;
use pqvpnd::net::{Network, ipv6_preflight, run_ip};

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

/// ipv6_policy = "fail" refuses while usable IPv6 exists, and a setup failure after the guard is up removes it.
fn ipv6_refusals() {
    ipv6_preflight(Ipv6Policy::Fail).expect("no IPv6 in a fresh namespace");
    ip("-6 addr add 2001:db8::2/64 dev pqup0 nodad");
    let error = ipv6_preflight(Ipv6Policy::Fail).unwrap_err();
    assert!(error.to_string().contains("ipv6_policy=fail"), "{error}");
    assert!(Network::up("pqfail0", Ipv4Addr::new(10, 8, 0, 2), 24, 1380, Ipv4Addr::new(192, 0, 2, 1), Ipv6Policy::Fail).is_err());
    assert!(run_ip(&["link".into(), "show".into(), "dev".into(), "pqfail0".into()], true).is_err(), "refused before leaving a TUN");
    ip("-6 addr del 2001:db8::2/64 dev pqup0");
    // No route to this server, so the bypass step fails after the guard went in: everything must be undone.
    let before = routes();
    assert!(Network::up("pqfail0", Ipv4Addr::new(10, 8, 0, 2), 24, 1380, Ipv4Addr::new(198, 51, 100, 1), Ipv6Policy::Block).is_err());
    assert!(!nft_tables().contains("pqvpn_client6_"), "guard removed after a failed setup");
    assert_eq!(routes(), before);
}

fn child() {
    let signals = pqvpnd::block_stop_signals().unwrap();
    // An uplink with a pre-existing host route to the "server", so the bypass route has something to restore.
    ip("link add pqup0 type dummy");
    ip("addr add 192.0.2.2/24 dev pqup0");
    ip("link set pqup0 up");
    ip("route add 192.0.2.1/32 dev pqup0 metric 77");
    ipv6_refusals();
    let before = routes();

    let network = Network::up("pqtest0", Ipv4Addr::new(10, 8, 0, 2), 24, 1380, Ipv4Addr::new(192, 0, 2, 1), Ipv6Policy::Block).unwrap();
    let table = network.ipv6_table.clone().expect("block installs the guard");
    assert!(nft_tables().contains(&format!("table ip6 {table}")), "IPv6 guard present while up");
    assert!(ip("-o addr show dev pqtest0").contains("10.8.0.2/24"), "TUN address");
    assert!(ip("-o link show dev pqtest0").contains("mtu 1380"), "TUN mtu");
    assert_eq!(std::fs::read_to_string("/proc/sys/net/ipv6/conf/pqtest0/disable_ipv6").unwrap().trim(), "1", "no IPv6 on the TUN");
    assert!(ip("route show exact 192.0.2.1/32").contains("dev pqup0"), "bypass route");
    assert_ne!(routes(), before, "routes changed while up");
    println!("ready");

    let signal = pqvpnd::wait_for_stop(&signals).unwrap();
    drop(network);
    assert_eq!(routes(), before, "every route restored after {signal:?}");
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
    println!("netns: ipv6 fail/block refusals and rollback, TUN up, bypass route, guard, SIGTERM cleanup restored everything: ok");
}
