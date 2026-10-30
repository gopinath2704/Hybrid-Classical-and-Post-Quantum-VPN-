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

The gate path is the one above: v2, cookies off, N=50, (loaded - baseline) / connected.
--data-plane / --handshake run the same definition on another backend (rows: pqvpn-dp-<x>-hs-<y>).

--dev is an unprivileged probe for development, NOT the gate: the server runs in its own process on
127.0.0.1 with an emulated TUN and the clients run in this process (profile dev-n=<N>[-concurrent]).
It tracks the gate closely for a staggered run but cannot replace it (no netns, no real TUN).
    python eval/measure_memory.py --dev --clients 50 [--concurrent]
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import tempfile
import threading
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
# TOML lines appended to every server and client config; empty is the published python/python path.
BACKEND_LINES: list[str] = []


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
                expected_vpn_subnet = "10.8.0.0/16"
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

    for path in [f"{srv_dir}/server.toml"] + [c["config"] for c in clients]:
        with open(path, "a") as f:
            f.writelines(line + "\n" for line in BACKEND_LINES)

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
        stdout=open(f"{c['dir']}/client.log", "w"), stderr=subprocess.STDOUT,
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
                print(f"\n  WARNING: client {i} failed to connect "
                      f"(see {topo['clients'][i]['dir']}/client.log)", flush=True)

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


_DEV_SERVER = """
import json, sys, threading, time
sys.path.insert(0, sys.argv[1])
import vpn.runtime as runtime
from vpn.config import ServerConfig
d, n, backend = sys.argv[2], int(sys.argv[3]), json.loads(sys.argv[4])
s = runtime.VPNServer(ServerConfig(listen_host="127.0.0.1", control_port=0, udp_port=0, protocol_version=2,
    server_identity_private_key=d + "/server.key", server_identity_public_key=d + "/server.pub",
    authorized_clients_file=d + "/clients.json", dev_emulated_tun=True, dns_servers=[], cookie_mode="off",
    max_clients=max(n + 10, 64), connections_per_source=10000, rate_limit_window=1.0, rekey_interval=86400,
    **backend))
threading.Thread(target=s.start, daemon=True).start()
while s.tcp is None or s.udp is None:
    time.sleep(0.01)
s.cfg.udp_port = s.udp.getsockname()[1]
print(json.dumps({"tcp": s.tcp.getsockname()[1]}), flush=True)
sys.stdin.read()
"""


def run_dev_measurement(n_clients: int, run_dir: str, backend: dict[str, str], concurrent: bool) -> dict:
    """Unprivileged probe: same arithmetic as the gate, server in its own process, emulated TUN."""
    from vpn.config import ClientConfig
    from vpn.identity import AuthorizedClients, generate_client_identity, generate_server_identity
    import vpn.runtime as runtime

    d = tempfile.mkdtemp(prefix=f"dev-n{n_clients}-", dir=run_dir)
    fp = generate_server_identity(Path(d, "server.key"), Path(d, "server.pub"))
    auth = AuthorizedClients(Path(d, "clients.json"))
    for i in range(n_clients):  # one directory each: the resumption ticket lives next to the key
        Path(d, f"c{i}").mkdir()
        generate_client_identity(Path(d, f"c{i}", "client.key"), Path(d, f"c{i}", "client.pub"))
        auth.authorize(Path(d, f"c{i}", "client.pub").read_bytes(), f"bench-{i}")
    print(f"\n--- dev N={n_clients} {'concurrent' if concurrent else 'staggered 0.3 s'} ---", flush=True)
    server = subprocess.Popen([sys.executable, "-c", _DEV_SERVER, str(_ROOT), d, str(n_clients), json.dumps(backend)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=str(_ROOT))
    clients: list = []
    try:
        port = json.loads(next(line for line in server.stdout if line.startswith("{")))["tcp"]
        time.sleep(2)
        baseline_rss = read_vmrss_kb(server.pid)

        def connect(i: int) -> None:
            client = runtime.VPNClient(ClientConfig(server_host="127.0.0.1", server_control_port=port,
                server_identity_public_key=f"{d}/server.pub", server_identity_fingerprint=fp,
                client_identity_private_key=f"{d}/c{i}/client.key", dev_emulated_tun=True,
                tun_name=f"pqm8d{i}", full_tunnel=False, dns_servers=[], **backend))
            try:
                client.connect()
                clients.append(client)
            except Exception as exc:
                print(f"\n  WARNING: client {i} failed to connect: {exc}", flush=True)

        if concurrent:
            threads = [threading.Thread(target=connect, args=(i,)) for i in range(n_clients)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        else:
            for i in range(n_clients):
                connect(i)
                time.sleep(0.3)
        time.sleep(2)
        loaded_rss = read_vmrss_kb(server.pid)
        connected = len(clients)
        per_session = (loaded_rss - baseline_rss) / connected if connected and baseline_rss and loaded_rss else None
        print(f"  {connected}/{n_clients} connected, VmRSS {baseline_rss} -> {loaded_rss} kB, "
              f"per session {per_session if per_session is None else round(per_session, 1)} kB", flush=True)
        return {"n_clients": n_clients, "connected": connected, "baseline_rss_kb": baseline_rss,
                "loaded_rss_kb": loaded_rss, "per_session_kb": per_session}
    finally:
        for client in clients:
            try:
                client.disconnect()
            except Exception:
                pass
        server.stdin.close()
        try:
            server.wait(10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def handshake_backend_available() -> bool:
    """True once ServerConfig has the phase 4 slice (b) handshake switch."""
    from vpn.config import ServerConfig
    return "handshake" in {f.name for f in dataclasses.fields(ServerConfig)}


def main():
    parser = argparse.ArgumentParser(
        description="M8: Memory per session — networked measurement")
    parser.add_argument("--clients", default="1,10,50",
                        help="Comma-separated client counts to test")
    parser.add_argument("--out", default="",
                        help="CSV output path")
    parser.add_argument("--data-plane", choices=("python", "rust"), default="python")
    parser.add_argument("--handshake", choices=("python", "rust"), default="python",
                        help="rust needs --data-plane rust (phase 4 slice b)")
    parser.add_argument("--dev", action="store_true",
                        help="unprivileged probe (server process, emulated TUN); not the gate path")
    parser.add_argument("--concurrent", action="store_true",
                        help="with --dev: start every client at once instead of 0.3 s apart")
    args = parser.parse_args()
    if args.concurrent and not args.dev:
        parser.error("--concurrent only applies to --dev (the gate path staggers clients 0.3 s apart)")
    if args.handshake == "rust":
        if args.data_plane != "rust":
            parser.error("--handshake rust requires --data-plane rust")
        if not handshake_backend_available():
            print("SKIP: handshake=rust backend unavailable (phase 4 slice b not landed)", file=sys.stderr)
            return
    backend = {key: value for key, value in (("data_plane", args.data_plane), ("handshake", args.handshake))
               if value != "python"}
    BACKEND_LINES.extend(f'{key} = "{value}"' for key, value in backend.items())
    system = "pqvpn" if not backend else f"pqvpn-dp-{args.data_plane}-hs-{args.handshake}"

    counts = [int(c) for c in args.clients.split(",")]
    run_dir = tempfile.mkdtemp(prefix="pqvpn-m8.")

    print("=== M8 Memory per Session", "(dev probe, NOT the gate path) ===" if args.dev else "(Networked) ===")
    print(f"Client counts: {counts}")

    csv_path = args.out or os.path.join(run_dir, "memory.csv")
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    csv_f = open(csv_path, "w", newline="")
    writer = csv.writer(csv_f)
    writer.writerow(CSV_COLUMNS)

    run_idx = 0
    for n in counts:
        if args.dev:
            result = run_dev_measurement(n, run_dir, backend, args.concurrent)
            profile = f"dev-n={n}" + ("-concurrent" if args.concurrent else "")
        else:
            result = run_measurement(n, run_dir)
            profile = f"n={n}"

        writer.writerow([system, profile, "baseline_rss_kb", run_idx,
                         result["baseline_rss_kb"], "kB"])
        run_idx += 1

        writer.writerow([system, profile, "loaded_rss_kb", run_idx,
                         result["loaded_rss_kb"], "kB"])
        run_idx += 1

        writer.writerow([system, profile, "connected_clients", run_idx,
                         result["connected"], "count"])
        run_idx += 1

        if result["per_session_kb"] is not None:
            writer.writerow([system, profile, "per_session_kb", run_idx,
                             f"{result['per_session_kb']:.1f}", "kB"])
            run_idx += 1

            writer.writerow([system, profile, "per_session_bytes", run_idx,
                             f"{result['per_session_kb'] * 1024:.0f}", "B"])
            run_idx += 1

    csv_f.close()
    print(f"\nResults: {csv_path}")


if __name__ == "__main__":
    main()
