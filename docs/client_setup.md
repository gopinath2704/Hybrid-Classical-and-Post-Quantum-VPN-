# Linux client setup

Status: **Deployable research/prototype PQ-VPN**. Use a separate Linux client after
native and root-namespace validation on a disposable VM. Routed IPv6, a kill switch,
dynamic authenticated PMTU, and post-compromise hybrid rekey remain future work.

Use the tested CPython 3.14.7, liboqs-python 0.16.0 and native liboqs 0.16.0 baseline.
Install native liboqs explicitly using the [server guide](server_deployment.md)
before importing the application. Create a fresh environment:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements-client.txt
.venv/bin/python -m vpn.cli client-key generate
# Provision server public identity + exact SHA-256 fingerprint securely.
# Send only config/client_identity_public.key to the administrator for authorization.
editor config/client.toml
.venv/bin/python -m vpn.cli doctor client --config config/client.toml
sudo -E .venv/bin/python -m vpn.cli client connect --config config/client.toml
```

Doctor checks the server pin, client private-key permissions, native crypto, TUN,
iproute2, DNS manager, name resolution, route to server, and obvious VPN-subnet
collisions. Check your LAN/container routes too. Set `expected_vpn_subnet` to the
provisioned server subnet; a different authenticated server subnet fails connection
setup. `server_control_port` configures TCP; authenticated CONFIG supplies UDP.
The obsolete `server_udp_port` setting is rejected rather than silently ignored.

`ping_interval=5`, `ping_timeout=4`, and `dead_peer_timeout=30` are validated seconds.
Only current authenticated server UDP (matching PONG, valid DATA, initial bind ACK)
refreshes the monotonic receive deadline. Outgoing PING, wrong endpoint/session,
replays, obsolete epochs, malformed records and bad AEAD do not. No valid UDP before
the deadline means FAILED, TUN/socket close, key wipe best-effort and route/DNS
cleanup even if TCP is still established. Manual reconnect is supported; no automatic
reconnect was added. Healthy PING/PONG refreshes server idle activity as well.

## DNS policy

`dns_mode="systemd-resolved"` is the safe default. For full tunnel, configured VPN
DNS (client override or authenticated server list) requires working resolvectl;
missing commands or partial failures abort setup and roll back routes/DNS. Full
mode routes DNS with `~.`. Install and enable systemd-resolved before connecting.
No permanent `/etc/resolv.conf` overwrite is performed.

`dns_mode="none"` explicitly opts out, emits a warning, and accepts unmanaged DNS
and possible leakage over a more-specific LAN route. It is not a safe default.
If both configured and advertised DNS lists are empty, no DNS is installed; this
also requires operator attention before full-tunnel deployment.

Split tunnel does not automatically install `~.`. Configure
`dns_routing_domains=["~corp.example"]` for intentional split DNS routing. An empty
list configures link DNS servers without a global routing-domain override; existing
systemd-resolved link policy determines their use. Setting `~.` explicitly requests
global routing. Inspect `resolvectl status` rather than assuming resolver selection.

## Separate real-client checks

Record `ip -4 route show` and `resolvectl status` before connecting. Verify the public
exit IP, TCP/UDP, the approved resolver and DNS routing domains after connecting.
Try the VPS's VPN IP for allowed ICMP; arbitrary host TCP/UDP, other VPN clients,
metadata and private destinations must fail unless the precise forwarded private
network is allowlisted. During traffic verify epoch changes and uninterrupted data.
Then block UDP temporarily or restart the server: the client must fail and restore
its prior routes and resolver state. Verify reconnect. Native DNS restoration is
still a real-systemd-client validation gate; namespace tests do not mutate host DNS.

The management API owns its own client; it cannot control a separately launched CLI
client. Use the optional API package and [management guide](management-api.md) only
when needed. Server authentication is ML-KEM-based; client authentication is classical
Ed25519, with hybrid X25519 + ML-KEM session establishment.

## Current validation record

The [2026-09-07 validation matrix](security_audit.md#final-validation--2026-09-07)
records a successful client doctor with native temporary identities, a matching pin,
managed DNS and a loopback server address used only for read-only route diagnostics.
This is not a connection to a deployed server. Re-run doctor against the real server
hostname and provisioned subnet before connecting. Omitted identity path fields use
the standard filenames beside the TOML, just like the explicit example paths.

The CLI dependencies are pinned in `requirements-client.txt` via the tested
constraints. Browser management is optional (`requirements-management.txt`); the
PyWebView desktop shell is separately installed and is not part of the validated
baseline. The Docker development profile lacks a running DNS manager by default;
its full-tunnel managed DNS must fail safely until the operator supplies one or
explicitly opts into unmanaged DNS. Root/TUN integration and real Linux-client DNS
restoration remain pending.
