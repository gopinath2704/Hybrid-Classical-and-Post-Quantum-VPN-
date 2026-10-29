#!/usr/bin/env python3
"""M5: Data-plane throughput — iperf3 + ping through PQ-VPN tunnel.

Starts a PQ-VPN server in a network namespace, connects one client,
and measures TCP/UDP throughput (iperf3) and RTT (ping) through the
tunnel.  Also measures bare-veth baseline RTT for comparison.

Requires root (netns + veth) and iperf3.

Topology:
    ns-server (192.0.2.1/24) <-- veth --> ns-client (192.0.2.2/24)
    VPN tunnel: 10.8.0.1 <--> assigned client IP

Profiles: lan, metro, continent, lossy-1, lossy-5, mtu-1280

Outputs unified CSV: system,profile,metric,run,value,unit

Usage:
    sudo env PATH="$PATH" python eval/measure_throughput.py \
        --profiles lan,metro --duration 20 --out results/m5/raw/throughput.csv

    --udp-rates 100M,500M,1G replaces the `-b 0` UDP flood with a fixed-rate goodput sweep.

    --data-plane rust needs pqvpn_core, so run the venv interpreter: sudo .venv/bin/python ...
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import textwrap
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

CSV_COLUMNS = ["system", "profile", "metric", "run", "value", "unit"]

PROFILES = {
    "lan":       {"rtt_ms": 0,   "loss_pct": 0, "mtu": 1500},
    "metro":     {"rtt_ms": 50,  "loss_pct": 0, "mtu": 1500},
    "continent": {"rtt_ms": 200, "loss_pct": 0, "mtu": 1500},
    "lossy-1":   {"rtt_ms": 50,  "loss_pct": 1, "mtu": 1500},
    "lossy-5":   {"rtt_ms": 50,  "loss_pct": 5, "mtu": 1500},
    "mtu-1280":  {"rtt_ms": 50,  "loss_pct": 0, "mtu": 1280},
}

PING_COUNT = 50
UDP_LOSS_LIMIT_PCT = 1.0


def udp_rate_mbps(rate: str) -> int:
    """'500M' / '1G' / '2.5G' -> offered rate in Mbit/s (the number in udp_*@<rate> metric names)."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([MG])", rate.strip(), re.IGNORECASE)
    if not m:
        raise ValueError(f"UDP rate must look like 500M or 2G, got {rate!r}")
    return round(float(m.group(1)) * (1000 if m.group(2).upper() == "G" else 1))


def udp_payload_len(profile: str) -> int:
    """Largest UDP payload whose inner packet fits the tunnel and whose outer packet fits the veth."""
    from vpn.config import ServerConfig
    from vpn.network import DATA_FRAME_OVERHEAD
    ip_udp = 20 + 8
    inner_mtu = min(ServerConfig().mtu, PROFILES[profile]["mtu"] - ip_udp - DATA_FRAME_OVERHEAD)
    return inner_mtu - ip_udp


def parse_iperf3_udp(stdout: str) -> dict:
    """iperf3 -u -J: sender rate, receiver goodput, jitter and loss (receiver-side, as iperf3 reports)."""
    data = json.loads(stdout)
    end = data["end"]
    summary = end["sum"]
    lost = summary.get("lost_percent", 0)
    sent = end.get("sum_sent", summary)["bits_per_second"] / 1e6
    received = end.get("sum_received")
    return {
        "throughput_mbps": summary["bits_per_second"] / 1e6,
        "sent_mbps": sent,
        "goodput_mbps": received["bits_per_second"] / 1e6 if received else sent * (1 - lost / 100),
        "jitter_ms": summary.get("jitter_ms", 0),
        "lost_pct": lost,
    }


def udp_sweep_rows(profile: str, results: dict[int, dict | None], run_idx: int) -> tuple[list, int]:
    """Per-rate rows plus the highest rate iperf3 really sent (>=95%) with loss under UDP_LOSS_LIMIT_PCT."""
    rows = []
    for mbps, udp in results.items():
        if udp is None:
            continue
        for metric, key, fmt, unit in (("udp_sent_mbps", "sent_mbps", ".1f", "Mbps"),
                                       ("udp_goodput_mbps", "goodput_mbps", ".1f", "Mbps"),
                                       ("udp_lost_pct", "lost_pct", ".3f", "%"),
                                       ("udp_jitter_ms", "jitter_ms", ".3f", "ms")):
            rows.append(["pqvpn", profile, f"{metric}@{mbps}", run_idx, format(udp[key], fmt), unit])
            run_idx += 1
    passing = [mbps for mbps, udp in results.items()
               if udp and udp["lost_pct"] < UDP_LOSS_LIMIT_PCT and udp["sent_mbps"] >= 0.95 * mbps]
    rows.append(["pqvpn", profile, "udp_max_rate_under_1pct_loss_mbps", run_idx, max(passing, default=0), "Mbps"])
    return rows, run_idx + 1


def setup_topology(run_dir: str, profile: str, protocol: str = "v2-ed25519",
                   data_plane: str = "python") -> dict:
    """Create server + client namespaces with veth + netem."""
    p = PROFILES[profile]
    tag = os.getpid()
    srv_ns = f"m5srv-{tag}"
    cli_ns = f"m5cli-{tag}"

    subprocess.run(["ip", "netns", "add", srv_ns], check=True)
    subprocess.run(["ip", "netns", "add", cli_ns], check=True)
    subprocess.run(["ip", "-n", srv_ns, "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "-n", cli_ns, "link", "set", "lo", "up"], check=True)

    subprocess.run(["ip", "link", "add", "m5s", "type", "veth",
                     "peer", "name", "m5c"], check=True)
    subprocess.run(["ip", "link", "set", "m5s", "netns", srv_ns], check=True)
    subprocess.run(["ip", "link", "set", "m5c", "netns", cli_ns], check=True)

    subprocess.run(["ip", "-n", srv_ns, "addr", "add", "192.0.2.1/24",
                     "dev", "m5s"], check=True)
    subprocess.run(["ip", "-n", cli_ns, "addr", "add", "192.0.2.2/24",
                     "dev", "m5c"], check=True)
    subprocess.run(["ip", "-n", srv_ns, "link", "set", "m5s", "up",
                     "mtu", str(p["mtu"])], check=True)
    subprocess.run(["ip", "-n", cli_ns, "link", "set", "m5c", "up",
                     "mtu", str(p["mtu"])], check=True)

    delay_each = p["rtt_ms"] // 2
    if delay_each > 0 or p["loss_pct"] > 0:
        netem = ["delay", f"{delay_each}ms"]
        if p["loss_pct"] > 0:
            netem += ["loss", f"{p['loss_pct']}%"]
        subprocess.run(["ip", "netns", "exec", srv_ns,
                         "tc", "qdisc", "add", "dev", "m5s",
                         "root", "netem"] + netem, check=True)
        subprocess.run(["ip", "netns", "exec", cli_ns,
                         "tc", "qdisc", "add", "dev", "m5c",
                         "root", "netem"] + netem, check=True)

    subprocess.run(["ip", "netns", "exec", cli_ns,
                     "ping", "-c1", "-W3", "192.0.2.1"],
                   capture_output=True, check=True)

    srv_dir = os.path.join(run_dir, "server")
    cli_dir = os.path.join(run_dir, "client")
    os.makedirs(srv_dir, exist_ok=True)
    os.makedirs(cli_dir, exist_ok=True)

    subprocess.run([sys.executable, "-m", "vpn.cli", "identity", "generate",
                    "--private", f"{srv_dir}/server.key",
                    "--public", f"{srv_dir}/server.pub"],
                   check=True, cwd=str(_ROOT))
    fp = subprocess.check_output(
        ["sha256sum", f"{srv_dir}/server.pub"]).decode().split()[0]

    keygen_cmd = [sys.executable, "-m", "vpn.cli", "client-key", "generate",
                  "--private", f"{cli_dir}/client.key",
                  "--public", f"{cli_dir}/client.pub"]
    if protocol == "v3-kem":
        keygen_cmd.append("--kem")  # ML-KEM-768 client identity for v3
    subprocess.run(keygen_cmd, check=True, cwd=str(_ROOT))
    pub_b64 = subprocess.check_output(
        ["base64", "-w0", f"{cli_dir}/client.pub"]).decode().strip()
    subprocess.run([sys.executable, "-m", "vpn.cli", "client", "authorize",
                    pub_b64,
                    "--database", f"{srv_dir}/authorized.json",
                    "--client-id", "bench-client"],
                   check=True, cwd=str(_ROOT))

    with open(f"{srv_dir}/server.toml", "w") as f:
        f.write(textwrap.dedent(f"""\
            [server]
            listen_host = "0.0.0.0"
            control_port = 51820
            udp_port = 51820
            vpn_subnet = "10.8.0.0/24"
            server_vpn_ip = "10.8.0.1"
            max_clients = 4
            handshake_timeout = 30
            rekey_interval = 86400
            outbound_interface = "m5s"
            dns_servers = []
            server_identity_private_key = "server.key"
            server_identity_public_key = "server.pub"
            authorized_clients_file = "authorized.json"
            connections_per_source = 100
            rate_limit_window = 1.0
            cookie_mode = "off"
        """))

    with open(f"{cli_dir}/client.toml", "w") as f:
        f.write(textwrap.dedent(f"""\
            [client]
            server_host = "192.0.2.1"
            server_control_port = 51820
            server_identity_fingerprint = "{fp}"
            server_identity_public_key = "../server/server.pub"
            client_identity_private_key = "client.key"
            full_tunnel = false
            dns_mode = "none"
            dns_servers = []
            tun_name = "pqm5t0"
        """))

    # v3-kem needs the negotiated protocol version on both ends and the
    # client's ML-KEM public key; data-plane throughput itself is unchanged
    # (AES-256-GCM frames either way), so this selects the handshake suite only.
    if protocol == "v3-kem":
        with open(f"{srv_dir}/server.toml", "a") as f:
            f.write("protocol_version = 3\n")
        with open(f"{cli_dir}/client.toml", "a") as f:
            f.write("protocol_version = 3\n")
            f.write('client_identity_public_key = "client.pub"\n')
    if data_plane == "rust":
        for path in (f"{srv_dir}/server.toml", f"{cli_dir}/client.toml"):
            with open(path, "a") as f:
                f.write('data_plane = "rust"\n')

    subprocess.run(["ip", "netns", "exec", srv_ns,
                     "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"],
                   check=True)

    return {
        "srv_ns": srv_ns, "cli_ns": cli_ns,
        "srv_dir": srv_dir, "cli_dir": cli_dir, "fp": fp,
    }


def start_server(topo: dict, run_dir: str) -> subprocess.Popen:
    log_path = os.path.join(run_dir, "server.log")
    log_f = open(log_path, "w")
    proc = subprocess.Popen(
        ["ip", "netns", "exec", topo["srv_ns"],
         sys.executable, "-m", "vpn.cli", "server",
         "--config", f"{topo['srv_dir']}/server.toml"],
        stdout=log_f, stderr=subprocess.STDOUT,
        cwd=str(_ROOT))
    time.sleep(2)
    if proc.poll() is not None:
        log_f.close()
        with open(log_path) as f:
            print(f"FATAL: server failed:\n{f.read()}", file=sys.stderr)
        sys.exit(1)
    return proc


def connect_client(topo: dict) -> subprocess.Popen:
    return subprocess.Popen(
        ["ip", "netns", "exec", topo["cli_ns"],
         sys.executable, "-m", "vpn.cli", "client", "connect",
         "--config", f"{topo['cli_dir']}/client.toml"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=str(_ROOT))


def wait_for_tunnel(topo: dict, timeout: float = 60) -> bool:
    for _ in range(int(timeout * 10)):
        ret = subprocess.run(
            ["ip", "netns", "exec", topo["cli_ns"],
             "ping", "-c1", "-W1", "10.8.0.1"],
            capture_output=True)
        if ret.returncode == 0:
            return True
        time.sleep(0.1)
    return False


def measure_ping(ns: str, target: str, count: int = PING_COUNT) -> float | None:
    ret = subprocess.run(
        ["ip", "netns", "exec", ns,
         "ping", "-c", str(count), "-i", "0.2", target],
        capture_output=True, text=True, timeout=count + 30)
    if ret.returncode != 0:
        return None
    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", ret.stdout)
    return float(m.group(1)) if m else None


def measure_iperf3_tcp(topo: dict, duration: int) -> dict | None:
    srv_proc = subprocess.Popen(
        ["ip", "netns", "exec", topo["srv_ns"],
         "iperf3", "-s", "-1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    try:
        ret = subprocess.run(
            ["ip", "netns", "exec", topo["cli_ns"],
             "iperf3", "-c", "10.8.0.1", "-t", str(duration), "-J"],
            capture_output=True, text=True, timeout=duration + 30)
    except subprocess.TimeoutExpired:
        srv_proc.kill()
        srv_proc.wait()
        return None

    try:
        srv_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv_proc.kill()
        srv_proc.wait()

    if ret.returncode != 0:
        print(f"  iperf3 TCP failed: {ret.stderr[:300]}", file=sys.stderr)
        return None

    try:
        data = json.loads(ret.stdout)
        return {
            "sent_mbps": data["end"]["sum_sent"]["bits_per_second"] / 1e6,
            "received_mbps": data["end"]["sum_received"]["bits_per_second"] / 1e6,
        }
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  iperf3 TCP parse error: {e}", file=sys.stderr)
        return None


def measure_iperf3_udp(topo: dict, duration: int, rate: str = "0",
                       length: int | None = None) -> dict | None:
    srv_proc = subprocess.Popen(
        ["ip", "netns", "exec", topo["srv_ns"],
         "iperf3", "-s", "-1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    try:
        ret = subprocess.run(
            ["ip", "netns", "exec", topo["cli_ns"],
             "iperf3", "-c", "10.8.0.1", "-u", "-b", rate,
             "-t", str(duration), "-J"] + (["-l", str(length)] if length else []),
            capture_output=True, text=True, timeout=duration + 30)
    except subprocess.TimeoutExpired:
        srv_proc.kill()
        srv_proc.wait()
        return None

    try:
        srv_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv_proc.kill()
        srv_proc.wait()

    if ret.returncode != 0:
        print(f"  iperf3 UDP failed: {ret.stderr[:300]}", file=sys.stderr)
        return None

    try:
        return parse_iperf3_udp(ret.stdout)
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  iperf3 UDP parse error: {e}", file=sys.stderr)
        return None


def cleanup(topo: dict, procs: list[subprocess.Popen]):
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    for ns in (topo.get("srv_ns"), topo.get("cli_ns")):
        if ns:
            subprocess.run(["ip", "netns", "del", ns], capture_output=True)


def run_profile(profile: str, run_dir: str, duration: int,
                run_idx: int, protocol: str = "v2-ed25519",
                data_plane: str = "python", udp_rates: list[str] | None = None) -> tuple[list, int]:
    mode_dir = os.path.join(run_dir, profile)
    os.makedirs(mode_dir, exist_ok=True)
    rows = []

    print(f"\n--- Profile: {profile} ({protocol}, {data_plane} data plane) ---")
    p = PROFILES[profile]
    print(f"  netem: rtt={p['rtt_ms']}ms  loss={p['loss_pct']}%  mtu={p['mtu']}")
    print("  Setting up topology...", flush=True)
    topo = setup_topology(mode_dir, profile, protocol, data_plane)
    server_proc = start_server(topo, mode_dir)
    client_proc = connect_client(topo)
    procs = [server_proc, client_proc]

    try:
        if not wait_for_tunnel(topo):
            print("  FATAL: tunnel failed to come up", file=sys.stderr)
            return rows, run_idx

        print("  Tunnel up.", flush=True)

        # Bare veth ping (baseline RTT without tunnel)
        print(f"  Bare veth ping ({PING_COUNT} packets)...", end="", flush=True)
        bare_rtt = measure_ping(topo["cli_ns"], "192.0.2.1")
        if bare_rtt is not None:
            print(f" avg={bare_rtt:.3f} ms")
            rows.append(["pqvpn", profile, "bare_rtt_ms", run_idx,
                          f"{bare_rtt:.3f}", "ms"])
            run_idx += 1
        else:
            print(" FAILED")

        # Tunnel ping
        print(f"  Tunnel ping ({PING_COUNT} packets)...", end="", flush=True)
        tunnel_rtt = measure_ping(topo["cli_ns"], "10.8.0.1")
        if tunnel_rtt is not None:
            print(f" avg={tunnel_rtt:.3f} ms")
            rows.append(["pqvpn", profile, "tunnel_rtt_ms", run_idx,
                          f"{tunnel_rtt:.3f}", "ms"])
            run_idx += 1
        else:
            print(" FAILED")

        # iperf3 TCP
        print(f"  iperf3 TCP ({duration}s)...", end="", flush=True)
        tcp = measure_iperf3_tcp(topo, duration)
        if tcp:
            print(f" sent={tcp['sent_mbps']:.1f} Mbps,"
                  f" received={tcp['received_mbps']:.1f} Mbps")
            rows.append(["pqvpn", profile, "tcp_sent_mbps", run_idx,
                          f"{tcp['sent_mbps']:.1f}", "Mbps"])
            run_idx += 1
            rows.append(["pqvpn", profile, "tcp_received_mbps", run_idx,
                          f"{tcp['received_mbps']:.1f}", "Mbps"])
            run_idx += 1
        else:
            print(" FAILED")

        time.sleep(2)

        if udp_rates:
            length = udp_payload_len(profile)
            sweep = {}
            for rate in udp_rates:
                print(f"  iperf3 UDP -b {rate} -l {length} ({duration}s)...", end="", flush=True)
                udp = measure_iperf3_udp(topo, duration, rate, length)
                sweep[udp_rate_mbps(rate)] = udp
                print(f" sent={udp['sent_mbps']:.1f} goodput={udp['goodput_mbps']:.1f} Mbps,"
                      f" loss={udp['lost_pct']:.3f}%" if udp else " FAILED")
                time.sleep(1)
            sweep_rows, run_idx = udp_sweep_rows(profile, sweep, run_idx)
            rows += sweep_rows
            print(f"  max rate with loss <{UDP_LOSS_LIMIT_PCT:g}%: {sweep_rows[-1][4]} Mbps")
            return rows, run_idx

        # iperf3 UDP
        print(f"  iperf3 UDP ({duration}s)...", end="", flush=True)
        udp = measure_iperf3_udp(topo, duration)
        if udp:
            print(f" throughput={udp['throughput_mbps']:.1f} Mbps,"
                  f" jitter={udp['jitter_ms']:.3f} ms,"
                  f" loss={udp['lost_pct']:.1f}%")
            rows.append(["pqvpn", profile, "udp_throughput_mbps", run_idx,
                          f"{udp['throughput_mbps']:.1f}", "Mbps"])
            run_idx += 1
            rows.append(["pqvpn", profile, "udp_jitter_ms", run_idx,
                          f"{udp['jitter_ms']:.3f}", "ms"])
            run_idx += 1
            rows.append(["pqvpn", profile, "udp_lost_pct", run_idx,
                          f"{udp['lost_pct']:.1f}", "%"])
            run_idx += 1
        else:
            print(" FAILED")

        return rows, run_idx

    finally:
        cleanup(topo, procs)


def main():
    parser = argparse.ArgumentParser(
        description="M5: Data-plane throughput — iperf3 + ping")
    parser.add_argument("--profiles",
                        default=",".join(PROFILES.keys()),
                        help="Comma-separated profiles to test")
    parser.add_argument("--duration", type=int, default=20,
                        help="iperf3 test duration in seconds (default: 20)")
    parser.add_argument("--out", default="",
                        help="CSV output path")
    parser.add_argument("--protocol", default="v2-ed25519",
                        choices=["v2-ed25519", "v3-kem"],
                        help="handshake suite (default: v2-ed25519). "
                             "Data-plane throughput is the same either way; "
                             "v3-kem exercises the v3 data path end-to-end.")
    parser.add_argument("--data-plane", default="python", choices=["python", "rust"],
                        help="per-packet loop on both ends (default: python); "
                             "rust needs pqvpn_core in the running interpreter")
    parser.add_argument("--udp-rates", default="",
                        help="comma-separated fixed UDP rates, e.g. 100M,500M,1G,2G,3G,4G: a goodput "
                             "sweep instead of the -b 0 flood (default: the -b 0 flood)")
    args = parser.parse_args()
    udp_rates = [r.strip() for r in args.udp_rates.split(",") if r.strip()]
    try:
        for rate in udp_rates:
            udp_rate_mbps(rate)
    except ValueError as e:
        parser.error(str(e))

    if subprocess.run(["which", "iperf3"], capture_output=True).returncode != 0:
        print("FATAL: iperf3 not found. Install with: apt install iperf3",
              file=sys.stderr)
        sys.exit(1)

    profiles = [p.strip() for p in args.profiles.split(",")]
    for p in profiles:
        if p not in PROFILES:
            print(f"unknown profile: {p}  (available: {', '.join(PROFILES)})",
                  file=sys.stderr)
            sys.exit(1)

    run_dir = subprocess.check_output(
        ["mktemp", "-d", "/tmp/pqvpn-m5.XXXXXX"]).decode().strip()

    print("=== M5 Data-Plane Throughput ===")
    print(f"Profiles: {profiles}")
    print(f"Protocol: {args.protocol}")
    print(f"Data plane: {args.data_plane}")
    print(f"iperf3 duration: {args.duration}s")

    csv_path = args.out or os.path.join(run_dir, "throughput.csv")
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    csv_f = open(csv_path, "w", newline="")
    writer = csv.writer(csv_f)
    writer.writerow(CSV_COLUMNS)

    run_idx = 0
    for profile in profiles:
        rows, run_idx = run_profile(profile, run_dir, args.duration, run_idx,
                                    args.protocol, args.data_plane, udp_rates)
        for row in rows:
            writer.writerow(row)
        csv_f.flush()

    csv_f.close()
    print(f"\nResults: {csv_path}")


if __name__ == "__main__":
    main()
