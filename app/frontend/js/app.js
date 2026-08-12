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

const API_BASE = `${window.location.origin}/api/v1`;
const WS_URL = `ws://${window.location.host}/ws/telemetry`;
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
    selectedServerId: 'fra-01',
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
    if (state.connectionState !== 'DISCONNECTED') return;

    try {
        updateConnectionUI('CONNECTING');
        const result = await apiPost('/vpn/connect', {
            server_id: state.selectedServerId,
        });
        state.connectionState = 'CONNECTED';
        state.sessionId = result.session_id;
        state.vpnIp = result.vpn_ip;
        updateConnectionUI('CONNECTED');
        refreshLogs();
    } catch (err) {
        console.error('Connect failed:', err);
        updateConnectionUI('DISCONNECTED');
    }
}

async function disconnectVPN() {
    if (state.connectionState !== 'CONNECTED') return;

    try {
        updateConnectionUI('DISCONNECTING');
        await apiPost('/vpn/disconnect');
        state.connectionState = 'DISCONNECTED';
        state.sessionId = '';
        state.vpnIp = '';
        state.uptimeSeconds = 0;
        updateConnectionUI('DISCONNECTED');
        refreshLogs();
    } catch (err) {
        console.error('Disconnect failed:', err);
        updateConnectionUI('CONNECTED');
    }
}

function toggleConnection() {
    if (state.connectionState === 'DISCONNECTED') {
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
    const pqBadge = $('#pq-badge');

    // Reset classes
    powerRing.className = 'power-ring';
    heroStatus.className = 'hero-status-text';
    stateEl.className = 'connection-state';

    switch (connState) {
        case 'CONNECTED':
            stateEl.textContent = 'Connected';
            stateEl.classList.add('connected');
            subtitleEl.textContent = 'Your connection is secure and encrypted';
            powerRing.classList.add('connected');
            heroStatus.textContent = 'CONNECTED';
            heroStatus.classList.add('connected');
            heroSub.textContent = 'Secure Tunnel Active';
            connectBtn.textContent = 'Disconnect';
            connectBtn.className = 'connect-btn disconnect';
            pqBadge.style.display = 'inline-flex';
            break;

        case 'CONNECTING':
            stateEl.textContent = 'Connecting...';
            stateEl.classList.add('connecting');
            subtitleEl.textContent = 'Establishing KEMTLS handshake...';
            powerRing.classList.add('connecting');
            heroStatus.textContent = 'CONNECTING';
            heroStatus.classList.add('connecting');
            heroSub.textContent = 'Negotiating Hybrid Keys...';
            connectBtn.textContent = 'Connecting...';
            connectBtn.className = 'connect-btn disconnect';
            connectBtn.style.pointerEvents = 'none';
            pqBadge.style.display = 'none';
            setTimeout(() => { connectBtn.style.pointerEvents = ''; }, 3000);
            break;

        case 'DISCONNECTING':
            stateEl.textContent = 'Disconnecting...';
            stateEl.classList.add('connecting');
            subtitleEl.textContent = 'Cleaning session keys...';
            heroStatus.textContent = 'DISCONNECTING';
            heroSub.textContent = 'Wiping session keys...';
            break;

        case 'DISCONNECTED':
        default:
            stateEl.textContent = 'Disconnected';
            stateEl.classList.add('disconnected');
            subtitleEl.textContent = 'Not connected to any server';
            heroStatus.textContent = 'DISCONNECTED';
            heroStatus.classList.add('disconnected');
            heroSub.textContent = 'Click to connect';
            connectBtn.textContent = 'Connect';
            connectBtn.className = 'connect-btn connect';
            pqBadge.style.display = 'none';
            break;
    }
}

function updateTelemetryUI(data) {
    // Update state from telemetry frame
    state.connectionState = data.connection_state;
    state.uptimeSeconds = data.uptime_seconds;
    state.downloadMbps = data.download_mbps;
    state.uploadMbps = data.upload_mbps;
    state.latencyMs = data.latency_ms;
    state.jitterMs = data.jitter_ms;
    state.lossRate = data.loss_rate;
    state.mtu = data.mtu;
    state.bytesSent = data.bytes_sent;
    state.bytesReceived = data.bytes_received;
    state.keyRotationRemaining = data.key_rotation_remaining;
    state.downloadHistory = data.download_history || [];
    state.uploadHistory = data.upload_history || [];
    state.latencyHistory = data.latency_history || [];
    state.lossHistory = data.loss_history || [];

    // Connection details
    const durationEl = $('#detail-duration');
    const ipEl = $('#detail-ip');
    const keyRotEl = $('#detail-key-rotation');

    if (durationEl) durationEl.textContent = formatUptime(state.uptimeSeconds);
    if (ipEl) ipEl.textContent = state.vpnIp || '—';
    if (keyRotEl) keyRotEl.textContent = formatKeyRotation(state.keyRotationRemaining);

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
    if (footerKeyRot) footerKeyRot.textContent = `Every ${Math.ceil(state.keyRotationRemaining / 60)} Minutes`;

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
    if (powerRing) {
        powerRing.addEventListener('click', toggleConnection);
    }

    // Connect/Disconnect button
    const connectBtn = $('#connect-btn');
    if (connectBtn) {
        connectBtn.addEventListener('click', toggleConnection);
    }

    // Server selector change
    const serverSelect = $('#server-select');
    if (serverSelect) {
        serverSelect.addEventListener('change', (e) => {
            state.selectedServerId = e.target.value;
            updateServerInfo();
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

    console.log('[PQ-VPN] Dashboard ready.');
});
