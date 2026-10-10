#!/usr/bin/env python3
"""M7: Cookie-flood behaviour — measure server resilience under ClientHello flood.

Sends spoofed/unique ClientHellos at a fixed rate from a flood source while
a legitimate client repeatedly connects through the tunnel.  Runs with
cookie_mode="off" and cookie_mode="always" to quantify the defence.

Requires root (netns + veth), native liboqs, and iproute2.

Topology:
    ns-server  (192.0.2.1) <-- veth --> ns-client (192.0.2.2)
                            <-- veth --> ns-flood  (192.0.2.3)

Outputs unified CSV: system,profile,metric,run,value,unit

Usage:
    sudo python eval/flood_clienthello.py \\
        --rates 0,100,1000,10000 --duration 15 --out results/m7/raw/flood.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import socket
import struct
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

MAGIC = 0x4856
PROTOCOL_VERSION = 0x20
MSG_CLIENT_HELLO = 1
HEADER_FORMAT = "!HBBH"
HEADER_SIZE = 6
CH_PAYLOAD_SIZE = 1312
CH_WIRE_SIZE = HEADER_SIZE + CH_PAYLOAD_SIZE  # 1318
TCP_LENGTH_PREFIX = 4

CSV_COLUMNS = ["system", "profile", "metric", "run", "value", "unit"]


def craft_clienthello() -> bytes:
    """Build a syntactically valid ClientHello with random fields."""
    payload = os.urandom(CH_PAYLOAD_SIZE)
    header = struct.pack(HEADER_FORMAT, MAGIC, PROTOCOL_VERSION,
                         MSG_CLIENT_HELLO, CH_PAYLOAD_SIZE)
    return header + payload


def tcp_frame(msg: bytes) -> bytes:
    return struct.pack("!I", len(msg)) + msg


def flood_worker(target_ip: str, target_port: int, rate: int,
                 duration: float, stop_event: threading.Event,
                 stats: dict) -> None:
    """Send ClientHellos at *rate* per second for *duration* seconds."""
    ch_frame = tcp_frame(craft_clienthello())
    sent = 0
    errors = 0
    interval = 1.0 / rate if rate > 0 else 0
    deadline = time.monotonic() + duration

    while time.monotonic() < deadline and not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_ip, target_port))
            s.sendall(ch_frame)
            sent += 1
            s.close()
        except OSError:
            errors += 1
        if interval > 0:
            next_send = time.monotonic() + interval
            while time.monotonic() < next_send and not stop_event.is_set():
                time.sleep(0.0001)

    stats["flood_sent"] = sent
    stats["flood_errors"] = errors


def legit_connect(run_dir: str, client_ns: str, config_path: str,
                  timeout_s: float = 30) -> tuple[bool, float]:
    """Run a real VPN client connect + ping and return (success, latency_ms)."""
    subprocess.run(
        ["ip", "-n", client_ns, "link", "del", "pqbench0"],
        capture_output=True)

    start = time.monotonic()
    proc = subprocess.Popen(
        ["ip", "netns", "exec", client_ns,
         sys.executable, "-m", "vpn.cli", "client", "connect",
         "--config", config_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=str(_ROOT))

    connected = False
    for _ in range(int(timeout_s * 20)):
        ret = subprocess.run(
            ["ip", "netns", "exec", client_ns,
             "ping", "-c1", "-W1", "10.8.0.1"],
            capture_output=True)
        if ret.returncode == 0:
            connected = True
            break
        time.sleep(0.05)

    elapsed_ms = (time.monotonic() - start) * 1000

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    return connected, elapsed_ms


def read_server_cpu(pid: int) -> float | None:
    """Read cumulative CPU (user+system) in seconds from /proc."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
        clk = os.sysconf("SC_CLK_TCK")
        utime = int(parts[13])
        stime = int(parts[14])
        return (utime + stime) / clk
    except (FileNotFoundError, IndexError, ValueError):
        return None


def setup_topology(run_dir: str, cookie_mode: str) -> dict:
    """Create namespaces, veth pairs, identities, configs.  Returns info dict."""
    tag = os.getpid()
    srv_ns = f"m7srv-{tag}"
    cli_ns = f"m7cli-{tag}"
    fld_ns = f"m7fld-{tag}"

    for ns in [srv_ns, cli_ns, fld_ns]:
        subprocess.run(["ip", "netns", "add", ns], check=True)
        subprocess.run(["ip", "-n", ns, "link", "set", "lo", "up"], check=True)

    subprocess.run(["ip", "link", "add", "m7s", "type", "veth",
                     "peer", "name", "m7c"], check=True)
    subprocess.run(["ip", "link", "set", "m7s", "netns", srv_ns], check=True)
    subprocess.run(["ip", "link", "set", "m7c", "netns", cli_ns], check=True)
    subprocess.run(["ip", "-n", srv_ns, "addr", "add", "192.0.2.1/24",
                     "dev", "m7s"], check=True)
    subprocess.run(["ip", "-n", cli_ns, "addr", "add", "192.0.2.2/24",
                     "dev", "m7c"], check=True)
    subprocess.run(["ip", "-n", srv_ns, "link", "set", "m7s", "up"], check=True)
    subprocess.run(["ip", "-n", cli_ns, "link", "set", "m7c", "up"], check=True)

    subprocess.run(["ip", "link", "add", "m7sf", "type", "veth",
                     "peer", "name", "m7f"], check=True)
    subprocess.run(["ip", "link", "set", "m7sf", "netns", srv_ns], check=True)
    subprocess.run(["ip", "link", "set", "m7f", "netns", fld_ns], check=True)
    subprocess.run(["ip", "-n", srv_ns, "addr", "add", "192.0.3.1/24",
                     "dev", "m7sf"], check=True)
    subprocess.run(["ip", "-n", fld_ns, "addr", "add", "192.0.3.2/24",
                     "dev", "m7f"], check=True)
    subprocess.run(["ip", "-n", srv_ns, "link", "set", "m7sf", "up"], check=True)
    subprocess.run(["ip", "-n", fld_ns, "link", "set", "m7f", "up"], check=True)

    subprocess.run(["ip", "netns", "exec", srv_ns,
                     "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"], check=True)

    srv_dir = os.path.join(run_dir, "server")
    cli_dir = os.path.join(run_dir, "client")
    os.makedirs(srv_dir, exist_ok=True)
    os.makedirs(cli_dir, exist_ok=True)

    subprocess.run([sys.executable, "-m", "vpn.cli", "identity", "generate",
                    "--private", f"{srv_dir}/server.key",
                    "--public", f"{srv_dir}/server.pub"],
                   check=True, cwd=str(_ROOT))
    subprocess.run([sys.executable, "-m", "vpn.cli", "client-key", "generate",
                    "--private", f"{cli_dir}/client.key",
                    "--public", f"{cli_dir}/client.pub"],
                   check=True, cwd=str(_ROOT))
    pub_b64 = subprocess.check_output(
        ["base64", "-w0", f"{cli_dir}/client.pub"]).decode().strip()
    subprocess.run([sys.executable, "-m", "vpn.cli", "client", "authorize",
                    pub_b64,
                    "--database", f"{srv_dir}/authorized.json",
                    "--client-id", "bench-client"],
                   check=True, cwd=str(_ROOT))
    fp = subprocess.check_output(
        ["sha256sum", f"{srv_dir}/server.pub"]).decode().split()[0]

    with open(f"{srv_dir}/server.toml", "w") as f:
        f.write(textwrap.dedent(f"""\
            [server]
            listen_host = "0.0.0.0"
            control_port = 51820
            udp_port = 51820
            vpn_subnet = "10.8.0.0/24"
            server_vpn_ip = "10.8.0.1"
            max_clients = 64
            handshake_timeout = 30
            rekey_interval = 3600
            outbound_interface = "m7s"
            dns_servers = []
            server_identity_private_key = "server.key"
            server_identity_public_key = "server.pub"
            authorized_clients_file = "authorized.json"
            connections_per_source = 10000
            rate_limit_window = 1.0
            cookie_mode = "{cookie_mode}"
            cookie_threshold = 10
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
            tun_name = "pqbench0"
        """))

    return {
        "srv_ns": srv_ns, "cli_ns": cli_ns, "fld_ns": fld_ns,
        "srv_dir": srv_dir, "cli_dir": cli_dir,
        "client_config": f"{cli_dir}/client.toml",
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


def cleanup_topology(topo: dict):
    for ns in [topo.get("srv_ns"), topo.get("cli_ns"), topo.get("fld_ns")]:
        if ns:
            subprocess.run(["ip", "netns", "del", ns],
                           capture_output=True)


def run_flood_trial(topo: dict, run_dir: str, rate: int, duration: float,
                    connects: int, server_proc: subprocess.Popen) -> dict:
    """Run one trial: flood at *rate* while measuring *connects* legit connects."""
    stop_flood = threading.Event()
    flood_stats: dict = {"flood_sent": 0, "flood_errors": 0}

    if rate > 0:
        flood_thread = threading.Thread(
            target=flood_worker,
            args=("192.0.3.1", 51820, rate, duration, stop_flood, flood_stats),
            daemon=True)
        flood_thread.start()
        time.sleep(1)

    cpu_before = read_server_cpu(server_proc.pid)
    wall_start = time.monotonic()

    results = []
    for c in range(connects):
        ok, ms = legit_connect(
            run_dir, topo["cli_ns"], topo["client_config"])
        results.append({"success": ok, "latency_ms": ms})
        time.sleep(0.5)

    wall_elapsed = time.monotonic() - wall_start
    cpu_after = read_server_cpu(server_proc.pid)

    stop_flood.set()
    if rate > 0:
        flood_thread.join(timeout=5)

    cpu_pct = None
    if cpu_before is not None and cpu_after is not None and wall_elapsed > 0:
        cpu_pct = ((cpu_after - cpu_before) / wall_elapsed) * 100

    successes = sum(1 for r in results if r["success"])
    latencies = [r["latency_ms"] for r in results if r["success"]]
    avg_latency = sum(latencies) / len(latencies) if latencies else -1
    median_latency = sorted(latencies)[len(latencies) // 2] if latencies else -1

    return {
        "rate": rate,
        "connects_attempted": connects,
        "connects_succeeded": successes,
        "avg_latency_ms": avg_latency,
        "median_latency_ms": median_latency,
        "cpu_pct": cpu_pct,
        "flood_sent": flood_stats["flood_sent"],
        "flood_errors": flood_stats["flood_errors"],
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(
        description="M7: Cookie-flood behaviour benchmark")
    parser.add_argument("--rates", default="0,100,1000",
                        help="Comma-separated flood rates (ClientHellos/s)")
    parser.add_argument("--duration", type=int, default=15,
                        help="Flood duration per trial (seconds)")
    parser.add_argument("--connects", type=int, default=5,
                        help="Legitimate connects per trial")
    parser.add_argument("--out", default="",
                        help="CSV output path")
    args = parser.parse_args()

    rates = [int(r) for r in args.rates.split(",")]
    run_dir = subprocess.check_output(
        ["mktemp", "-d", "/tmp/pqvpn-m7.XXXXXX"]).decode().strip()

    print("=== M7 Cookie-Flood Behaviour ===")
    print(f"Rates: {rates}  Duration: {args.duration}s  "
          f"Connects/trial: {args.connects}")

    csv_path = args.out or os.path.join(run_dir, "flood.csv")
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    csv_f = open(csv_path, "w", newline="")
    writer = csv.writer(csv_f)
    writer.writerow(CSV_COLUMNS)

    run_idx = 0

    for cookie_mode in ["off", "always"]:
        print(f"\n--- cookie_mode={cookie_mode} ---")
        topo = setup_topology(run_dir, cookie_mode)
        server_proc = start_server(topo, run_dir)

        try:
            for rate in rates:
                label = f"cookie-{cookie_mode}"
                print(f"  rate={rate}/s ... ", end="", flush=True)

                trial = run_flood_trial(
                    topo, run_dir, rate, args.duration,
                    args.connects, server_proc)

                for i, r in enumerate(trial["results"]):
                    writer.writerow([
                        f"pqvpn-{label}", f"flood-{rate}",
                        "connect_time_ms", run_idx,
                        f"{r['latency_ms']:.1f}" if r["success"] else "-1",
                        "ms"])
                    run_idx += 1

                writer.writerow([
                    f"pqvpn-{label}", f"flood-{rate}",
                    "connects_succeeded", run_idx,
                    trial["connects_succeeded"], "count"])
                run_idx += 1

                writer.writerow([
                    f"pqvpn-{label}", f"flood-{rate}",
                    "connects_attempted", run_idx,
                    trial["connects_attempted"], "count"])
                run_idx += 1

                writer.writerow([
                    f"pqvpn-{label}", f"flood-{rate}",
                    "avg_connect_time_ms", run_idx,
                    f"{trial['avg_latency_ms']:.1f}", "ms"])
                run_idx += 1

                writer.writerow([
                    f"pqvpn-{label}", f"flood-{rate}",
                    "median_connect_time_ms", run_idx,
                    f"{trial['median_latency_ms']:.1f}", "ms"])
                run_idx += 1

                if trial["cpu_pct"] is not None:
                    writer.writerow([
                        f"pqvpn-{label}", f"flood-{rate}",
                        "server_cpu_pct", run_idx,
                        f"{trial['cpu_pct']:.1f}", "percent"])
                    run_idx += 1

                writer.writerow([
                    f"pqvpn-{label}", f"flood-{rate}",
                    "flood_sent", run_idx,
                    trial["flood_sent"], "count"])
                run_idx += 1

                ok = trial["connects_succeeded"]
                n = trial["connects_attempted"]
                lat = trial["median_latency_ms"]
                cpu = trial["cpu_pct"]
                cpu_s = f"{cpu:.0f}%" if cpu is not None else "n/a"
                print(f"{ok}/{n} connects  median={lat:.0f}ms  "
                      f"cpu={cpu_s}  flood_sent={trial['flood_sent']}")

        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait()
            cleanup_topology(topo)

    csv_f.close()
    print(f"\nResults: {csv_path}")


if __name__ == "__main__":
    main()
