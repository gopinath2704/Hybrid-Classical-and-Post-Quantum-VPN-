/** Management contract: docs/management-api.md. Values come from runtime measurements. */
const API_BASE = `${location.origin}/api/v1`;
let connectionState = 'DISCONNECTED';
let busy = false;
const text = (id, value) => { const node = document.getElementById(id); if (node) node.textContent = value ?? '—'; };
async function request(path, method = 'GET') {
    let token = sessionStorage.getItem('pqvpnManagementToken');
    if (!token) { token = prompt('PQVPN management token:') || ''; sessionStorage.setItem('pqvpnManagementToken', token); }
    const response = await fetch(`${API_BASE}${path}`, {method, headers: {Authorization: `Bearer ${token}`}});
    if (!response.ok) throw new Error(`Management request failed (${response.status})`);
    return response.json();
}
function render(data) {
    connectionState = data.connection_state;
    text('connection-state', connectionState);
    text('hero-status-text', connectionState);
    text('connection-subtitle', data.error || (connectionState === 'CONNECTED' ? 'Tunnel active' : 'Uses config/client.toml; start the VPN server separately'));
    text('hero-status-sub', data.error || 'PQVPN KEMTLS-inspired v2');
    text('connect-btn', connectionState === 'CONNECTED' ? 'Disconnect' : 'Connect');
    const ring = document.getElementById('power-ring');
    if (ring) ring.className = `power-ring ${connectionState === 'CONNECTED' ? 'connected' : ''}`;
    text('detail-ip', data.client_vpn_ip);
    text('detail-duration', `${Math.floor(data.uptime_seconds)} s`);
    text('footer-uptime', `${Math.floor(data.uptime_seconds)} s`);
    text('detail-pqc-mode', data.pqc_mode);
    text('detail-tun-mode', data.tun_mode);
    text('badge-pqc-mode', `PQC: ${data.pqc_mode}`);
    text('badge-tun-mode', `TUN: ${data.tun_mode || 'inactive'}`);
    text('crypto-posture', data.is_quantum_safe ? 'Hybrid PQ key establishment; classical client auth' : 'Native PQC unavailable / mock');
    const countdown = data.rekey_countdown == null ? '—' : `${Math.ceil(data.rekey_countdown)} s`;
    text('detail-key-rotation', countdown); text('footer-key-rotation', countdown);
    text('mtu-value', data.tun_mtu); text('epoch-value', data.epoch);
    const network = data.network || {};
    text('latency-value', network.probes_received ? `${network.rtt_ms.toFixed(1)} ms` : '—');
    text('jitter-value', network.probes_received ? `${network.jitter_ms.toFixed(1)} ms` : '—');
    text('loss-value', network.probes_sent ? `${(network.loss_rate * 100).toFixed(2)}%` : '—');
}
async function refresh() {
    try { render(await request('/vpn/status')); }
    catch (error) { text('connection-subtitle', error.message); }
}
async function toggle() {
    if (busy) return;
    busy = true;
    try { await request(connectionState === 'CONNECTED' ? '/vpn/disconnect' : '/vpn/connect', 'POST'); await refresh(); }
    catch (error) { text('connection-subtitle', error.message); }
    finally { busy = false; }
}
document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('connect-btn')?.addEventListener('click', toggle);
    document.getElementById('power-ring')?.addEventListener('click', toggle);
    try {
        const {servers} = await request('/vpn/servers');
        const select = document.getElementById('server-select');
        if (select) select.replaceChildren(...servers.map(server => new Option(`${server.name} (${server.host}:${server.port})`, server.id)));
        text('detail-location', servers[0]?.host);
    } catch (error) { text('connection-subtitle', error.message); }
    await refresh(); setInterval(refresh, 2000);
});
