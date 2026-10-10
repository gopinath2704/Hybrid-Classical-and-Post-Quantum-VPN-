#!/usr/bin/env python3
"""M8: Memory per session — networked measurement.

Starts a PQ-VPN server, connects N real clients from separate namespaces,
and reads the server's VmRSS from /proc/<pid>/status.  Repeats for each
value of N to derive per-session memory overhead.

Requires root (netns + veth).

Topology:
    ns-server (10.0.0.1/16) <-- veth --> ns-client-{i} (10.0.{hi}.{lo}/16)

Outputs unified CSV: system,profile,metric,run,value,unit

Usage:
    sudo env PATH="$PATH" python eval/measure_memory.py \
        --clients 1,10,50 --out results/m8/raw/memory.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

CSV_COLUMNS = ["system", "profile", "metric", "run", "value", "unit"]


def read_vmrss_kb(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, IndexError, ValueError):
        pass
    return None


def setup_topology(run_dir: str, n_clients: int) -> dict:
    """Create server + N client namespaces with point-to-point veths."""
    tag = os.getpid()
    srv_ns = f"m8srv-{tag}"
    srv_dir = os.path.join(run_dir, "server")
    os.makedirs(srv_dir, exist_ok=True)

    subprocess.run(["ip", "netns", "add", srv_ns], check=True)
    subprocess.run(["ip", "-n", srv_ns, "link", "set", "lo", "up"], check=True)

    subprocess.run([sys.executable, "-m", "vpn.cli", "identity", "generate",
                    "--private", f"{srv_dir}/server.key",
                    "--public", f"{srv_dir}/server.pub"],
                   check=True, cwd=str(_ROOT))
    fp = subprocess.check_output(
        ["sha256sum", f"{srv_dir}/server.pub"]).decode().split()[0]

    clients = []
    for i in range(n_clients):
        cli_ns = f"m8cli{i}-{tag}"
        cli_dir = os.path.join(run_dir, f"client{i}")
        os.makedirs(cli_dir, exist_ok=True)

        subprocess.run(["ip", "netns", "add", cli_ns], check=True)
        subprocess.run(["ip", "-n", cli_ns, "link", "set", "lo", "up"],
                       check=True)

        vs = f"m8s{i}"
        vc = f"m8c{i}"
        subprocess.run(["ip", "link", "add", vs, "type", "veth",
                         "peer", "name", vc], check=True)
        subprocess.run(["ip", "link", "set", vs, "netns", srv_ns], check=True)
        subprocess.run(["ip", "link", "set", vc, "netns", cli_ns], check=True)

        hi = (i + 1) >> 8
        lo = (i + 1) & 0xFF
        srv_ip = f"10.0.{hi}.{lo}"
        cli_ip = f"10.1.{hi}.{lo}"

        subprocess.run(["ip", "-n", srv_ns, "addr", "add",
                         f"{srv_ip}/32", "dev", vs,
                         "peer", f"{cli_ip}/32"], check=True)
        subprocess.run(["ip", "-n", cli_ns, "addr", "add",
                         f"{cli_ip}/32", "dev", vc,
                         "peer", f"{srv_ip}/32"], check=True)
        subprocess.run(["ip", "-n", srv_ns, "link", "set", vs, "up"],
                       check=True)
        subprocess.run(["ip", "-n", cli_ns, "link", "set", vc, "up"],
                       check=True)

        subprocess.run([sys.executable, "-m", "vpn.cli", "client-key",
                        "generate",
                        "--private", f"{cli_dir}/client.key",
                        "--public", f"{cli_dir}/client.pub"],
                       check=True, cwd=str(_ROOT))
        pub_b64 = subprocess.check_output(
            ["base64", "-w0", f"{cli_dir}/client.pub"]).decode().strip()
        subprocess.run([sys.executable, "-m", "vpn.cli", "client", "authorize",
                        pub_b64,
                        "--database", f"{srv_dir}/authorized.json",
                        "--client-id", f"bench-{i}"],
                       check=True, cwd=str(_ROOT))

        with open(f"{cli_dir}/client.toml", "w") as f:
            f.write(textwrap.dedent(f"""\
                [client]
                server_host = "{srv_ip}"
                server_control_port = 51820
                server_identity_fingerprint = "{fp}"
                server_identity_public_key = "../server/server.pub"
                client_identity_private_key = "client.key"
                full_tunnel = false
                dns_mode = "none"
                dns_servers = []
                tun_name = "pqm8t{i}"
            """))

        clients.append({"ns": cli_ns, "dir": cli_dir,
                         "config": f"{cli_dir}/client.toml"})

    subprocess.run(["ip", "netns", "exec", srv_ns,
                     "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"],
                   check=True)

    with open(f"{srv_dir}/server.toml", "w") as f:
        f.write(textwrap.dedent(f"""\
            [server]
            listen_host = "0.0.0.0"
            control_port = 51820
            udp_port = 51820
            vpn_subnet = "10.8.0.0/16"
            server_vpn_ip = "10.8.0.1"
            max_clients = {max(n_clients + 10, 64)}
            handshake_timeout = 60
            rekey_interval = 86400
            outbound_interface = ""
            dns_servers = []
            server_identity_private_key = "server.key"
            server_identity_public_key = "server.pub"
            authorized_clients_file = "authorized.json"
            connections_per_source = 10000
            rate_limit_window = 1.0
            cookie_mode = "off"
        """))

    return {
        "srv_ns": srv_ns, "srv_dir": srv_dir,
        "clients": clients, "fp": fp,
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


def connect_client(topo: dict, idx: int) -> subprocess.Popen:
    c = topo["clients"][idx]
    return subprocess.Popen(
        ["ip", "netns", "exec", c["ns"],
         sys.executable, "-m", "vpn.cli", "client", "connect",
         "--config", c["config"]],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=str(_ROOT))


def wait_for_tunnel(topo: dict, idx: int, timeout: float = 60) -> bool:
    c = topo["clients"][idx]
    for _ in range(int(timeout * 10)):
        ret = subprocess.run(
            ["ip", "netns", "exec", c["ns"],
             "ping", "-c1", "-W1", "10.8.0.1"],
            capture_output=True)
        if ret.returncode == 0:
            return True
        time.sleep(0.1)
    return False


def cleanup(topo: dict, client_procs: list[subprocess.Popen],
            server_proc: subprocess.Popen | None):
    for p in client_procs:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    if server_proc:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait()
    for c in topo.get("clients", []):
        subprocess.run(["ip", "netns", "del", c["ns"]], capture_output=True)
    if topo.get("srv_ns"):
        subprocess.run(["ip", "netns", "del", topo["srv_ns"]],
                       capture_output=True)


def run_measurement(n_clients: int, run_dir: str) -> dict:
    mode_dir = os.path.join(run_dir, f"n{n_clients}")
    os.makedirs(mode_dir, exist_ok=True)

    print(f"\n--- N={n_clients} clients ---")
    print("  Setting up topology...", flush=True)
    topo = setup_topology(mode_dir, n_clients)
    server_proc = start_server(topo, mode_dir)
    client_procs = []

    try:
        baseline_rss = read_vmrss_kb(server_proc.pid)
        print(f"  Server baseline VmRSS: {baseline_rss} kB")

        print(f"  Connecting {n_clients} clients...", end="", flush=True)
        for i in range(n_clients):
            p = connect_client(topo, i)
            client_procs.append(p)
            time.sleep(0.3)

        connected = 0
        for i in range(n_clients):
            if wait_for_tunnel(topo, i, timeout=60):
                connected += 1
            else:
                print(f"\n  WARNING: client {i} failed to connect", flush=True)

        time.sleep(2)
        loaded_rss = read_vmrss_kb(server_proc.pid)
        print(f" {connected}/{n_clients} connected")
        print(f"  Server VmRSS with {connected} clients: {loaded_rss} kB")

        per_session = None
        if baseline_rss is not None and loaded_rss is not None and connected > 0:
            per_session = (loaded_rss - baseline_rss) / connected
            print(f"  Per-session overhead: {per_session:.1f} kB "
                  f"({per_session * 1024:.0f} B)")

        return {
            "n_clients": n_clients,
            "connected": connected,
            "baseline_rss_kb": baseline_rss,
            "loaded_rss_kb": loaded_rss,
            "per_session_kb": per_session,
        }

    finally:
        cleanup(topo, client_procs, server_proc)


def main():
    parser = argparse.ArgumentParser(
        description="M8: Memory per session — networked measurement")
    parser.add_argument("--clients", default="1,10,50",
                        help="Comma-separated client counts to test")
    parser.add_argument("--out", default="",
                        help="CSV output path")
    args = parser.parse_args()

    counts = [int(c) for c in args.clients.split(",")]
    run_dir = subprocess.check_output(
        ["mktemp", "-d", "/tmp/pqvpn-m8.XXXXXX"]).decode().strip()

    print("=== M8 Memory per Session (Networked) ===")
    print(f"Client counts: {counts}")

    csv_path = args.out or os.path.join(run_dir, "memory.csv")
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    csv_f = open(csv_path, "w", newline="")
    writer = csv.writer(csv_f)
    writer.writerow(CSV_COLUMNS)

    run_idx = 0
    for n in counts:
        result = run_measurement(n, run_dir)

        writer.writerow(["pqvpn", f"n={n}", "baseline_rss_kb", run_idx,
                         result["baseline_rss_kb"], "kB"])
        run_idx += 1

        writer.writerow(["pqvpn", f"n={n}", "loaded_rss_kb", run_idx,
                         result["loaded_rss_kb"], "kB"])
        run_idx += 1

        writer.writerow(["pqvpn", f"n={n}", "connected_clients", run_idx,
                         result["connected"], "count"])
        run_idx += 1

        if result["per_session_kb"] is not None:
            writer.writerow(["pqvpn", f"n={n}", "per_session_kb", run_idx,
                             f"{result['per_session_kb']:.1f}", "kB"])
            run_idx += 1

            writer.writerow(["pqvpn", f"n={n}", "per_session_bytes", run_idx,
                             f"{result['per_session_kb'] * 1024:.0f}", "B"])
            run_idx += 1

    csv_f.close()
    print(f"\nResults: {csv_path}")


if __name__ == "__main__":
    main()
