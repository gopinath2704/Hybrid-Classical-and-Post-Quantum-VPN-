"""Provisioning and Linux VPN client/server command line."""
from __future__ import annotations
import argparse, base64, logging, signal, sys, time
from pathlib import Path
from crypto.hybrid_crypto import get_crypto_status
from vpn.config import load_client_config,load_server_config
from vpn.identity import AuthorizedClients,generate_client_identity,generate_server_identity
from vpn.runtime import VPNClient,VPNServer

def main():
    p=argparse.ArgumentParser(prog="python -m vpn.cli"); p.add_argument("-v","--verbose",action="store_true"); sub=p.add_subparsers(dest="command",required=True)
    doctor=sub.add_parser("doctor"); doctor.add_argument("role", choices=["server", "client"]); doctor.add_argument("--config", required=True)
    identity=sub.add_parser("identity"); ids=identity.add_subparsers(dest="action",required=True); gen=ids.add_parser("generate"); gen.add_argument("--private",default="config/server_identity_private.key"); gen.add_argument("--public",default="config/server_identity_public.key")
    ck=sub.add_parser("client-key"); cks=ck.add_subparsers(dest="action",required=True); cg=cks.add_parser("generate"); cg.add_argument("--private",default="config/client_identity_private.key"); cg.add_argument("--public",default="config/client_identity_public.key")
    client_admin=sub.add_parser("client"); ca=client_admin.add_subparsers(dest="action",required=True)
    auth=ca.add_parser("authorize"); auth.add_argument("public_key"); auth.add_argument("--database",default="config/authorized_clients.json"); auth.add_argument("--client-id"); auth.add_argument("--vpn-ip")
    rev=ca.add_parser("revoke"); rev.add_argument("fingerprint"); rev.add_argument("--database",default="config/authorized_clients.json")
    connect=ca.add_parser("connect"); connect.add_argument("--config",default="config/client.toml"); connect.add_argument("--dev-emulated-tun",action="store_true"); connect.add_argument("--allow-mock-pqc",action="store_true",help="explicitly permit insecure mock PQC for tests/development")
    server=sub.add_parser("server"); server.add_argument("--config",default="config/server.toml"); server.add_argument("--dev-emulated-tun",action="store_true"); server.add_argument("--allow-mock-pqc",action="store_true",help="explicitly permit insecure mock PQC for tests/development")
    args=p.parse_args(); logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    if args.command=="doctor":
        from vpn.doctor import run
        sys.exit(run(args.role, args.config))
    if args.command=="identity":
        fp=generate_server_identity(Path(args.private),Path(args.public)); print(f"server identity fingerprint: {fp}"); return
    if args.command=="client-key":
        fp=generate_client_identity(Path(args.private),Path(args.public)); print(f"client identity fingerprint: {fp}"); return
    if args.command=="client" and args.action=="authorize":
        raw=Path(args.public_key).read_bytes() if Path(args.public_key).exists() else base64.b64decode(args.public_key,validate=True)
        print(AuthorizedClients(Path(args.database)).authorize(raw,args.client_id,args.vpn_ip)); return
    if args.command=="client" and args.action=="revoke":
        if not AuthorizedClients(Path(args.database)).revoke(args.fingerprint): sys.exit("client fingerprint not found")
        print("revoked"); return
    status=get_crypto_status()
    dev_mode=getattr(args,"dev_emulated_tun",False)
    if not status["is_quantum_safe"]:
        if status["pqc_mode"]=="mock_sha_fallback" and getattr(args,"allow_mock_pqc",False): logging.critical("*** INSECURE MOCK PQC ACTIVE: NOT QUANTUM SAFE; DEVELOPMENT ONLY ***")
        else: sys.exit("native ML-KEM-768 unavailable; production start refused")
    if args.command=="server":
        cfg=load_server_config(args.config); cfg.dev_emulated_tun=args.dev_emulated_tun
        service=VPNServer(cfg); signal.signal(signal.SIGTERM,lambda *_:service.stop())
        try:service.start()
        except KeyboardInterrupt:service.stop()
    else:
        cfg=load_client_config(args.config); cfg.dev_emulated_tun=args.dev_emulated_tun; service=VPNClient(cfg)
        signal.signal(signal.SIGTERM,lambda *_:service.stop_event.set()); info=service.connect(); print(f"connected: {info['client_vpn_ip']} via UDP {info['udp_port']}")
        try:
            service.stop_event.wait()
        except KeyboardInterrupt:pass
        finally:service.disconnect()
        if getattr(service, "state", "") == "FAILED": sys.exit(service.error)
if __name__=="__main__":main()
