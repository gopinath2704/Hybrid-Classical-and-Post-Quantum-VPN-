/**
 * PQ-VPN Desktop Application — UI Controller
 *
 * Manages the dashboard state, REST API interactions, real-time WebSocket
 * telemetry feed, Chart.js graph rendering, and all interactive UI behavior.
 *
 * Architecture:
 *   - REST Client: connect/disconnect/status/servers/logs via fetch()
 *   - WebSocket Client: auto-reconnecting telemetry feed at ws://host/ws/telemetry
 *   - Chart.js Manager: bandwidth (dual-line) + latency + packet loss mini-charts
 *   - State Machine: DISCONNECTED → CONNECTING → CONNECTED → DISCONNECTING
 */

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

const isFileProto = window.location.protocol === 'file:' || !window.location.host;
const API_BASE = isFileProto ? 'http://127.0.0.1:8000/api/v1' : `${window.location.origin}/api/v1`;
const WS_URL = isFileProto 
    ? 'ws://127.0.0.1:8000/ws/telemetry' 
    : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/telemetry`;
const STATUS_POLL_INTERVAL = 2000; // ms
const WS_RECONNECT_DELAY = 2000;  // ms

// ─────────────────────────────────────────────────────────────────────────────
// Application State
// ─────────────────────────────────────────────────────────────────────────────

const state = {
    connectionState: 'DISCONNECTED',
    sessionId: '',
    vpnIp: '',
    uptimeSeconds: 0,
    selectedServerId: 'local-test',
    servers: [],

    // Telemetry
    downloadMbps: 0,
    uploadMbps: 0,
    latencyMs: 0,
    jitterMs: 0,
    lossRate: 0,
    mtu: 1500,
    bytesSent: 0,
    bytesReceived: 0,
    keyRotationRemaining: 300,

    // Crypto posture (updated by fetchCryptoStatus)
    pqcMode: null,
    tunMode: null,
    isQuantumSafe: null,
    isMockPqc: false,
    tunModeLabel: null,

    // Chart history
    downloadHistory: [],
    uploadHistory: [],
    latencyHistory: [],
    lossHistory: [],

    // Activity log
    logs: [],
};


// ─────────────────────────────────────────────────────────────────────────────
// DOM References
// ─────────────────────────────────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ─────────────────────────────────────────────────────────────────────────────
// Utility Functions
// ─────────────────────────────────────────────────────────────────────────────

function formatUptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(i > 1 ? 2 : 0)} ${units[i]}`;
}

function formatSpeed(mbps) {
    if (mbps >= 1000) return `${(mbps / 1000).toFixed(2)} Gbps`;
    return `${mbps.toFixed(1)} Mbps`;
}

function formatKeyRotation(seconds) {
    const m = Math.floor(seconds / 60);
    const s = Math.floor(seconds % 60);
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}


// ─────────────────────────────────────────────────────────────────────────────
// REST API Client
// ─────────────────────────────────────────────────────────────────────────────

async function apiGet(path) {
    const res = await fetch(`${API_BASE}${path}`);
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
}

async function apiPost(path, params = {}) {
    const query = new URLSearchParams(params).toString();
    const url = query ? `${API_BASE}${path}?${query}` : `${API_BASE}${path}`;
    const res = await fetch(url, { method: 'POST' });
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
}


// ─────────────────────────────────────────────────────────────────────────────
// Connection Actions
// ─────────────────────────────────────────────────────────────────────────────

async function connectVPN() {
    if (state.connectionState !== 'DISCONNECTED' && state.connectionState !== 'ERROR') return;

    // Determine server_id (custom or dropdown)
    let params = { server_id: state.selectedServerId };
    const customGroup = $('#custom-server-group');
    if (customGroup && customGroup.style.display !== 'none') {
        const host = $('#custom-host')?.value.trim();
        const port = parseInt($('#custom-port')?.value || '51820');
        if (host) {
            // Use local-test profile but override host via query params
            params = { server_id: 'local-test', host, port };
        }
    }

    try {
        updateConnectionUI('CONNECTING');
        const result = await apiPost('/vpn/connect', params);
        state.sessionId = result.session_id || '';
        state.vpnIp = result.vpn_ip || '';
        state.pqcMode = result.pqc_mode || '';
        state.tunMode = result.tun_mode || '';
        state.isQuantumSafe = result.is_quantum_safe || false;
        updateConnectionUI('CONNECTED');
        refreshLogs();
        fetchCryptoStatus();
    } catch (err) {
        console.error('Connect failed:', err);
        updateConnectionUI('ERROR');
        setTimeout(() => updateConnectionUI('DISCONNECTED'), 3000);
    }
}

async function disconnectVPN() {
    if (state.connectionState !== 'CONNECTED') return;

    try {
        updateConnectionUI('DISCONNECTING');
        await apiPost('/vpn/disconnect');
        state.sessionId = '';
        state.vpnIp = '';
        state.uptimeSeconds = 0;
        state.tunMode = null;
        state.pqcMode = null;
        updateConnectionUI('DISCONNECTED');
        refreshLogs();
    } catch (err) {
        console.error('Disconnect failed:', err);
        updateConnectionUI('CONNECTED');
    }
}

async function rekeyVPN() {
    if (state.connectionState !== 'CONNECTED') return;
    try {
        const result = await apiPost('/vpn/rekey');
        console.log('[PQ-VPN] Keys rotated — nonce:', result.nonce);
        refreshLogs();
    } catch (err) {
        console.error('Rekey failed:', err);
    }
}

function toggleConnection() {
    if (state.connectionState === 'DISCONNECTED' || state.connectionState === 'ERROR') {
        connectVPN();
    } else if (state.connectionState === 'CONNECTED') {
        disconnectVPN();
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// UI Update Functions
// ─────────────────────────────────────────────────────────────────────────────

function updateConnectionUI(connState) {
    state.connectionState = connState;
    const stateEl = $('#connection-state');
    const subtitleEl = $('#connection-subtitle');
    const powerRing = $('#power-ring');
    const heroStatus = $('#hero-status-text');
    const heroSub = $('#hero-status-sub');
    const connectBtn = $('#connect-btn');
    const pqBadgeGroup = $('#pq-badge-group');
    const pqBadgeLive = $('#pq-badge-live');
    const pqBadgeEmulated = $('#pq-badge-emulated');
    const pqBadgeMock = $('#pq-badge-mock');

    // Reset classes
    if (powerRing) powerRing.className = 'power-ring';
    if (heroStatus) heroStatus.className = 'hero-status-text';
    if (stateEl) stateEl.className = 'connection-state';

    const hideBadges = () => {
        if (pqBadgeGroup) pqBadgeGroup.style.display = 'none';
    };
    const showBadges = () => {
        if (pqBadgeGroup) pqBadgeGroup.style.display = 'flex';
        // Show live/emulated/mock based on current crypto posture
        if (pqBadgeLive) pqBadgeLive.style.display = state.isQuantumSafe ? 'inline-flex' : 'none';
        if (pqBadgeEmulated) pqBadgeEmulated.style.display = (state.tunMode && state.tunMode.includes('SOCKET')) ? 'inline-flex' : 'none';
        if (pqBadgeMock) pqBadgeMock.style.display = (!state.isQuantumSafe && state.pqcMode === 'mock_sha_fallback') ? 'inline-flex' : 'none';
    };

    switch (connState) {
        case 'CONNECTED':
            if (stateEl) { stateEl.textContent = 'Connected'; stateEl.classList.add('connected'); }
            if (subtitleEl) subtitleEl.textContent = 'Your connection is secure and encrypted';
            if (powerRing) powerRing.classList.add('connected');
            if (heroStatus) { heroStatus.textContent = 'CONNECTED'; heroStatus.classList.add('connected'); }
            if (heroSub) heroSub.textContent = 'Secure Tunnel Active';
            if (connectBtn) { connectBtn.textContent = 'Disconnect'; connectBtn.className = 'connect-btn disconnect'; }
            showBadges();
            break;

        case 'CONNECTING':
            if (stateEl) { stateEl.textContent = 'Connecting...'; stateEl.classList.add('connecting'); }
            if (subtitleEl) subtitleEl.textContent = 'Establishing KEMTLS handshake...';
            if (powerRing) powerRing.classList.add('connecting');
            if (heroStatus) { heroStatus.textContent = 'CONNECTING'; heroStatus.classList.add('connecting'); }
            if (heroSub) heroSub.textContent = 'Negotiating Hybrid Keys...';
            if (connectBtn) { connectBtn.textContent = 'Connecting...'; connectBtn.className = 'connect-btn disconnect'; connectBtn.style.pointerEvents = 'none'; }
            hideBadges();
            setTimeout(() => { if (connectBtn) connectBtn.style.pointerEvents = ''; }, 30000);
            break;

        case 'DISCONNECTING':
            if (stateEl) { stateEl.textContent = 'Disconnecting...'; stateEl.classList.add('connecting'); }
            if (subtitleEl) subtitleEl.textContent = 'Wiping session keys...';
            if (heroStatus) { heroStatus.textContent = 'DISCONNECTING'; }
            if (heroSub) heroSub.textContent = 'Wiping session keys...';
            hideBadges();
            break;

        case 'ERROR':
            if (stateEl) { stateEl.textContent = 'Error'; stateEl.classList.add('disconnected'); }
            if (subtitleEl) subtitleEl.textContent = 'Connection failed — see logs';
            if (heroStatus) { heroStatus.textContent = 'ERROR'; heroStatus.classList.add('disconnected'); }
            if (heroSub) heroSub.textContent = 'Check logs and retry';
            if (connectBtn) { connectBtn.textContent = 'Connect'; connectBtn.className = 'connect-btn connect'; }
            hideBadges();
            break;

        case 'DISCONNECTED':
        default:
            if (stateEl) { stateEl.textContent = 'Disconnected'; stateEl.classList.add('disconnected'); }
            if (subtitleEl) subtitleEl.textContent = 'Not connected to any server';
            if (heroStatus) { heroStatus.textContent = 'DISCONNECTED'; heroStatus.classList.add('disconnected'); }
            if (heroSub) heroSub.textContent = 'Click to connect';
            if (connectBtn) { connectBtn.textContent = 'Connect'; connectBtn.className = 'connect-btn connect'; }
            hideBadges();
            break;
    }
}

/**
 * Fetch the runtime PQC/TUN status and update topbar mode badges.
 */
async function fetchCryptoStatus() {
    try {
        const status = await apiGet('/crypto/status');
        state.pqcMode = status.pqc_mode;
        state.isQuantumSafe = status.is_quantum_safe;
        state.isMockPqc = status.allow_mock_pqc;

        // Update topbar badges
        const badgePqc = $('#badge-pqc-mode');
        const badgeTun = $('#badge-tun-mode');

        if (badgePqc) {
            badgePqc.textContent = `PQC: ${status.pqc_mode}`;
            badgePqc.className = 'mode-badge ' + (status.is_quantum_safe ? 'mode-badge--live' : (status.allow_mock_pqc ? 'mode-badge--mock' : 'mode-badge--error'));
        }
        if (badgeTun && state.tunMode) {
            const isNative = !state.tunMode.includes('SOCKET');
            badgeTun.textContent = `TUN: ${isNative ? 'NATIVE' : 'SOCKET_PIPE'}`;
            badgeTun.className = 'mode-badge ' + (isNative ? 'mode-badge--live' : 'mode-badge--emulated');
        }
    } catch (e) {
        console.warn('[PQ-VPN] Could not fetch crypto status:', e.message);
    }
}

function updateTelemetryUI(data) {
    // Update state from telemetry frame
    state.connectionState = data.connection_state;
    state.uptimeSeconds = data.uptime_seconds || 0;
    state.downloadMbps = data.download_mbps || 0;
    state.uploadMbps = data.upload_mbps || 0;
    state.latencyMs = data.latency_ms || 0;
    state.jitterMs = data.jitter_ms || 0;
    state.lossRate = data.loss_rate || 0;
    state.mtu = data.mtu || 1500;
    state.bytesSent = data.bytes_sent || 0;
    state.bytesReceived = data.bytes_received || 0;
    state.keyRotationRemaining = data.key_rotation_remaining || 0;
    state.downloadHistory = data.download_history || [];
    state.uploadHistory = data.upload_history || [];
    state.latencyHistory = data.latency_history || [];
    state.lossHistory = data.loss_history || [];

    // Update mode from live telemetry
    if (data.pqc_mode) state.pqcMode = data.pqc_mode;
    if (data.tun_mode) {
        state.tunMode = data.tun_mode;
        const badgeTun = $('#badge-tun-mode');
        if (badgeTun) {
            const isNative = !data.tun_mode.includes('SOCKET');
            badgeTun.textContent = `TUN: ${isNative ? 'NATIVE' : 'SOCKET_PIPE'}`;
            badgeTun.className = 'mode-badge ' + (isNative ? 'mode-badge--live' : 'mode-badge--emulated');
        }
    }

    // Connection details
    const durationEl = $('#detail-duration');
    const ipEl = $('#detail-ip');
    const keyRotEl = $('#detail-key-rotation');
    const tunModeEl = $('#detail-tun-mode');
    const pqcModeEl = $('#detail-pqc-mode');

    if (durationEl) durationEl.textContent = formatUptime(state.uptimeSeconds);
    if (ipEl) ipEl.textContent = state.vpnIp || data.vpn_ip || '—';
    if (keyRotEl) keyRotEl.textContent = formatKeyRotation(state.keyRotationRemaining);
    if (tunModeEl) tunModeEl.textContent = data.tun_mode || '—';
    if (pqcModeEl) pqcModeEl.textContent = data.pqc_mode || '—';

    // Bandwidth header value
    const bwValue = $('#bandwidth-value');
    if (bwValue) bwValue.textContent = formatSpeed(state.downloadMbps);

    // Mini stats
    const latencyValue = $('#latency-value');
    const lossValue = $('#loss-value');
    if (latencyValue) latencyValue.textContent = `${state.latencyMs.toFixed(1)} ms`;
    if (lossValue) lossValue.textContent = `${(state.lossRate * 100).toFixed(2)}%`;

    // Footer values
    const footerUptime = $('#footer-uptime');
    const footerDataSent = $('#footer-data-sent');
    const footerDataRecv = $('#footer-data-recv');
    const footerKeyRot = $('#footer-key-rotation');

    if (footerUptime) footerUptime.textContent = formatUptime(state.uptimeSeconds);
    if (footerDataSent) footerDataSent.textContent = `↑ ${formatBytes(state.bytesSent)}`;
    if (footerDataRecv) footerDataRecv.textContent = `↓ ${formatBytes(state.bytesReceived)}`;
    if (footerKeyRot) footerKeyRot.textContent = `Every ${Math.ceil((state.keyRotationRemaining || 60) / 60)} Minutes`;

    // Update charts
    updateCharts();
}


// ─────────────────────────────────────────────────────────────────────────────
// Chart.js Integration
// ─────────────────────────────────────────────────────────────────────────────

let bandwidthChart = null;
let latencyChart = null;
let lossChart = null;

function initCharts() {
    // Chart.js global defaults
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.color = '#5A6478';

    const commonScaleOpts = {
        grid: {
            color: 'rgba(255, 255, 255, 0.04)',
            drawBorder: false,
        },
        ticks: {
            maxTicksLimit: 5,
            font: { family: "'JetBrains Mono', monospace", size: 10 },
        },
    };

    const timeLabels = Array.from({ length: 120 }, (_, i) => {
        const sec = -60 + i * 0.5;
        return sec % 15 === 0 ? `${sec}s` : '';
    });

    // ─── Bandwidth Chart ───
    const bwCtx = document.getElementById('bandwidth-chart');
    if (bwCtx) {
        bandwidthChart = new Chart(bwCtx, {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [
                    {
                        label: 'Download',
                        data: new Array(120).fill(0),
                        borderColor: '#00E676',
                        backgroundColor: 'rgba(0, 230, 118, 0.08)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0,
                    },
                    {
                        label: 'Upload',
                        data: new Array(120).fill(0),
                        borderColor: '#3B82F6',
                        backgroundColor: 'rgba(59, 130, 246, 0.05)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 1.5,
                        pointRadius: 0,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                interaction: { intersect: false, mode: 'index' },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#1A2235',
                        titleColor: '#E8ECF4',
                        bodyColor: '#8B95A8',
                        borderColor: '#1C2640',
                        borderWidth: 1,
                        cornerRadius: 8,
                        padding: 10,
                        callbacks: {
                            label: (ctx) => `${ctx.dataset.label}: ${formatSpeed(ctx.parsed.y)}`,
                        },
                    },
                },
                scales: {
                    x: {
                        ...commonScaleOpts,
                        ticks: {
                            ...commonScaleOpts.ticks,
                            maxTicksLimit: 8,
                            callback: function (val, idx) {
                                return this.getLabelForValue(val);
                            },
                        },
                    },
                    y: {
                        ...commonScaleOpts,
                        min: 0,
                        ticks: {
                            ...commonScaleOpts.ticks,
                            callback: (val) => formatSpeed(val),
                        },
                    },
                },
            },
        });
    }

    // ─── Latency Mini Chart ───
    const latCtx = document.getElementById('latency-chart');
    if (latCtx) {
        latencyChart = new Chart(latCtx, {
            type: 'line',
            data: {
                labels: new Array(120).fill(''),
                datasets: [{
                    data: new Array(120).fill(0),
                    borderColor: '#00F0FF',
                    backgroundColor: 'rgba(0, 240, 255, 0.08)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 1.5,
                    pointRadius: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 200 },
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
                scales: {
                    x: { display: false },
                    y: { display: false, min: 0 },
                },
            },
        });
    }

    // ─── Packet Loss Mini Chart ───
    const lossCtx = document.getElementById('loss-chart');
    if (lossCtx) {
        lossChart = new Chart(lossCtx, {
            type: 'line',
            data: {
                labels: new Array(120).fill(''),
                datasets: [{
                    data: new Array(120).fill(0),
                    borderColor: '#F59E0B',
                    backgroundColor: 'rgba(245, 158, 11, 0.08)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 1.5,
                    pointRadius: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 200 },
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
                scales: {
                    x: { display: false },
                    y: { display: false, min: 0 },
                },
            },
        });
    }
}

function updateCharts() {
    if (bandwidthChart) {
        bandwidthChart.data.datasets[0].data = state.downloadHistory;
        bandwidthChart.data.datasets[1].data = state.uploadHistory;
        bandwidthChart.update('none');
    }
    if (latencyChart) {
        latencyChart.data.datasets[0].data = state.latencyHistory;
        latencyChart.update('none');
    }
    if (lossChart) {
        lossChart.data.datasets[0].data = state.lossHistory;
        lossChart.update('none');
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Activity Logs
// ─────────────────────────────────────────────────────────────────────────────

async function refreshLogs() {
    try {
        const data = await apiGet('/logs?limit=10');
        state.logs = data.logs;
        renderLogs();
    } catch (err) {
        console.warn('Failed to fetch logs:', err);
    }
}

function renderLogs() {
    const container = $('#activity-list');
    if (!container) return;

    container.innerHTML = state.logs.map(log => `
        <div class="activity-item fade-in">
            <span class="activity-time">${log.time}</span>
            <span class="activity-dot ${log.level}"></span>
            <span class="activity-message">${highlightLogMessage(log.message)}</span>
        </div>
    `).join('');
}

function highlightLogMessage(msg) {
    // Bold key phrases
    return msg
        .replace(/(Connected to .+?)(?= —|$)/g, '<strong>$1</strong>')
        .replace(/(KEMTLS Handshake Completed)/g, '<strong>$1</strong>')
        .replace(/(Disconnected)/g, '<strong>$1</strong>')
        .replace(/(PQ-VPN Client)/g, '<strong>$1</strong>');
}


// ─────────────────────────────────────────────────────────────────────────────
// WebSocket Telemetry Client (Auto-Reconnecting)
// ─────────────────────────────────────────────────────────────────────────────

let ws = null;
let wsReconnectTimer = null;

function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) return;

    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        console.log('[WS] Telemetry stream connected');
        const indicator = $('#ws-indicator');
        if (indicator) indicator.style.background = '#00E676';
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'telemetry') {
                updateTelemetryUI(data);
            }
        } catch (e) {
            console.warn('[WS] Parse error:', e);
        }
    };

    ws.onclose = () => {
        console.log('[WS] Disconnected — reconnecting in', WS_RECONNECT_DELAY, 'ms');
        const indicator = $('#ws-indicator');
        if (indicator) indicator.style.background = '#EF4444';
        scheduleReconnect();
    };

    ws.onerror = (err) => {
        console.warn('[WS] Error:', err);
        ws.close();
    };
}

function scheduleReconnect() {
    if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
    wsReconnectTimer = setTimeout(connectWebSocket, WS_RECONNECT_DELAY);
}


// ─────────────────────────────────────────────────────────────────────────────
// Server List
// ─────────────────────────────────────────────────────────────────────────────

async function loadServers() {
    try {
        const data = await apiGet('/vpn/servers');
        state.servers = data.servers;

        const selector = $('#server-select');
        if (selector) {
            selector.innerHTML = data.servers.map(s =>
                `<option value="${s.id}">${s.flag} ${s.location}</option>`
            ).join('');
            selector.value = state.selectedServerId;
        }

        // Update server detail
        updateServerInfo();
    } catch (err) {
        console.warn('Failed to load servers:', err);
    }
}

function updateServerInfo() {
    const server = state.servers.find(s => s.id === state.selectedServerId);
    if (!server) return;

    const locEl = $('#detail-location');
    if (locEl) locEl.textContent = `${server.location} ${server.flag}`;
}


// ─────────────────────────────────────────────────────────────────────────────
// Navigation
// ─────────────────────────────────────────────────────────────────────────────

function setupNavigation() {
    $$('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            $$('.nav-link').forEach(l => l.classList.remove('active'));
            link.classList.add('active');
        });
    });
}


// ─────────────────────────────────────────────────────────────────────────────
// Event Listeners & Initialization
// ─────────────────────────────────────────────────────────────────────────────

function setupEventListeners() {
    // Power ring click
    const powerRing = $('#power-ring');
    if (powerRing) powerRing.addEventListener('click', toggleConnection);

    // Connect/Disconnect button
    const connectBtn = $('#connect-btn');
    if (connectBtn) connectBtn.addEventListener('click', toggleConnection);

    // Server selector change
    const serverSelect = $('#server-select');
    if (serverSelect) {
        serverSelect.addEventListener('change', (e) => {
            state.selectedServerId = e.target.value;
            updateServerInfo();
        });
    }

    // Custom server toggle
    const toggleCustom = $('#toggle-custom-server');
    const customGroup = $('#custom-server-group');
    if (toggleCustom && customGroup) {
        toggleCustom.addEventListener('click', () => {
            const visible = customGroup.style.display !== 'none';
            customGroup.style.display = visible ? 'none' : 'flex';
            toggleCustom.textContent = visible ? '✏️' : '✕';
            // Show/hide standard server selector
            const serverSel = $('.server-selector');
            if (serverSel) serverSel.style.opacity = visible ? '1' : '0.4';
        });
    }
}

// Periodic log refresh
setInterval(() => {
    if (state.connectionState === 'CONNECTED') {
        refreshLogs();
    }
}, 5000);


// ─────────────────────────────────────────────────────────────────────────────
// Boot
// ─────────────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    console.log('[PQ-VPN] Initializing dashboard...');

    // Initialize UI
    updateConnectionUI('DISCONNECTED');
    setupNavigation();
    setupEventListeners();

    // Load data
    loadServers();
    refreshLogs();

    // Initialize charts
    initCharts();

    // Connect WebSocket telemetry
    connectWebSocket();

    // Fetch crypto / PQC status to populate mode badges
    fetchCryptoStatus();

    console.log('[PQ-VPN] Dashboard ready.');
});
