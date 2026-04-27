let ws = null;
let isMonitoring = false;
let currentFilter = 'all';
let latestReports = [];
let reconnectRequested = false;
let pendingStartPayload = null;
let statusTimer = null;
const runtimeClient = window.SecflowTaskRuntime || {};
const createManagedTaskPage = runtimeClient.createManagedTaskPage;
const escapeHTML = runtimeClient.escapeHTML || fallbackEscapeHTML;
const loadJSONStorage = runtimeClient.loadJSONStorage || fallbackLoadJSONStorage;
const saveJSONStorage = runtimeClient.saveJSONStorage || fallbackSaveJSONStorage;
let managedPage = null;

const STORAGE_KEY = 'lan_monitor_preferences';
const STATUS_CLEAR_DELAY_MS = 5000;
const RECONNECT_DELAY_MS = 1200;
const RISK_LEVELS = new Set(['high', 'medium', 'low']);

const CATEGORY_LABELS = {
    video: '视频',
    stock: '股票',
    social: '社交',
    game: '游戏',
    shopping: '购物',
    work: '办公',
    malicious: '恶意',
    unknown: 'Unknown'
};

const CATEGORY_COLORS = {
    video: '#e74c3c',
    stock: '#e67e22',
    social: '#3498db',
    game: '#9b59b6',
    shopping: '#f39c12',
    work: '#27ae60',
    malicious: '#c0392b',
    unknown: '#95a5a6'
};

const STATUS_COLORS = {
    info: '#3498db',
    error: '#e74c3c',
    success: '#27ae60',
    monitoring: '#9b59b6'
};

const interfaceSelect = document.getElementById('interface');
const threatIntelSelect = document.getElementById('threatIntel');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const statusMessage = document.getElementById('statusMessage');
const reportsContainer = document.getElementById('reportsContainer');

const totalIPsEl = document.getElementById('totalIPs');
const highRiskIPsEl = document.getElementById('highRiskIPs');
const mediumRiskIPsEl = document.getElementById('mediumRiskIPs');
const lowRiskIPsEl = document.getElementById('lowRiskIPs');

document.addEventListener('DOMContentLoaded', init);

async function init() {
    setupEventListeners();
    setupManagedPage();
    await loadInterfaces();
    restorePreferences();
    await restoreRuntime();
}

function setupManagedPage() {
    if (!createManagedTaskPage) {
        return;
    }

    managedPage = createManagedTaskPage({
        runtimePath: '/api/runtime/lan-monitor',
        wsPath: '/ws/lan-monitor',
        reconnectMs: RECONNECT_DELAY_MS,
        onSocketOpen: (_event, activeSocket) => {
            ws = activeSocket;
        },
        onMessage: handleSocketMessage,
        onError: handleSocketError,
        onSocketClose: handleSocketClose
    });
}

async function loadInterfaces() {
    try {
        const response = await fetch('/api/interfaces');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const interfaces = await response.json();
        if (!Array.isArray(interfaces) || interfaces.length === 0) {
            interfaceSelect.innerHTML = '<option value="">No interfaces found</option>';
            return;
        }

        interfaceSelect.innerHTML = interfaces.map((iface) => {
            const rawName = iface.rawName || iface.name || '';
            const name = iface.name || rawName || 'Unnamed interface';
            return `<option value="${escapeHTML(rawName)}">${escapeHTML(name)}</option>`;
        }).join('');
    } catch (error) {
        console.error('load interfaces failed', error);
        interfaceSelect.innerHTML = '<option value="">加载失败</option>';
    }
}

function setupEventListeners() {
    startBtn.addEventListener('click', startMonitoring);
    stopBtn.addEventListener('click', stopMonitoring);
    interfaceSelect.addEventListener('change', persistPreferences);
    threatIntelSelect.addEventListener('change', persistPreferences);

    document.querySelectorAll('.filter-btn').forEach((button) => {
        button.addEventListener('click', handleFilterClick);
    });
}

function handleFilterClick(event) {
    const button = event.currentTarget;
    const nextFilter = button.dataset.filter || 'all';

    document.querySelectorAll('.filter-btn').forEach((item) => item.classList.remove('active'));
    button.classList.add('active');
    currentFilter = nextFilter;
    persistPreferences();
    renderReports();
}

async function restoreRuntime() {
    try {
        const restoreOptions = {
            onCommand: restoreCommandFields,
            onResume: (runtime) => {
                reconnectRequested = true;
                isMonitoring = true;
                updateUIState();
                showStatus('Monitoring in background, reconnected', 'monitoring');
                if (!runtime.active) {
                    showStatus('Task is recovering, monitor session reconnected', 'monitoring');
                }
            }
        };
        if (!managedPage) {
            console.error('managed task runtime client is unavailable');
            return;
        }

        await managedPage.restoreRuntime(restoreOptions);
    } catch (error) {
        console.error('restore lan runtime failed', error);
    }
}

function restoreCommandFields(command) {
    if (command.interface) {
        interfaceSelect.value = command.interface;
    }
    if (command.no_threat_intel === 'true') {
        threatIntelSelect.value = 'disabled';
    }
    persistPreferences();
}

function startMonitoring() {
    const iface = interfaceSelect.value;
    if (!iface) {
        alert('请先选择网卡');
        return;
    }

    persistPreferences();

    pendingStartPayload = {
        action: 'start',
        interface: iface,
        no_threat_intel: threatIntelSelect.value === 'disabled' ? 'true' : 'false'
    };

    reconnectRequested = true;
    isMonitoring = true;
    updateUIState();
    showStatus('正在启动监控...', 'monitoring');

    if (managedPage) {
        managedPage.start(pendingStartPayload);
        pendingStartPayload = null;
        return;
    }

    if (sendPendingStart()) {
        return;
    }
    ensureSocket();
}

function stopMonitoring() {
    reconnectRequested = false;
    pendingStartPayload = null;

    sendSocketPayload({ action: 'stop' });

    isMonitoring = false;
    updateUIState();
    showStatus('Monitoring stopped', 'info');
}

function sendPendingStart() {
    if (!pendingStartPayload) {
        return false;
    }

    if (!sendSocketPayload(pendingStartPayload)) {
        return false;
    }

    pendingStartPayload = null;
    return true;
}

function handleSocketMessage(data) {
    handleMessage(data);
}

function handleSocketError(error, context) {
    if (context && context.phase === 'parse') {
        console.error('parse message failed', error, context.raw);
        return;
    }

    showStatus('连接异常', 'error');
}

function handleSocketClose() {
    ws = null;
    if (!reconnectRequested && !pendingStartPayload) {
        isMonitoring = false;
        updateUIState();
    }
}

function ensureSocket() {
    if (managedPage) {
        ws = managedPage.ensureSocket();
        return;
    }

    console.error('managed task runtime client is unavailable');
}

function sendSocketPayload(payload) {
    if (managedPage) {
        if (payload && payload.action === 'start') {
            return managedPage.start(payload);
        }
        if (payload && payload.action === 'stop') {
            return managedPage.stop(payload);
        }
        return managedPage.send(payload);
    }

    console.error('managed task runtime client is unavailable');
    return false;
}

function handleMessage(data) {
    const payload = data.payload || data;

    switch (data.type) {
        case 'status':
            showStatus(data.message || payload.message || 'Monitoring', 'monitoring');
            break;
        case 'lan_report':
        case 'behavior_report':
            latestReports = Array.isArray(payload.reports) ? payload.reports : [];
            updateStats(payload.total_ips || latestReports.length);
            renderReports();
            isMonitoring = true;
            updateUIState();
            break;
        case 'security_alert':
            showStatus(`风险告警: ${payload.ip || '--'} -> ${payload.domain || '--'}`, 'error');
            break;
        case 'error':
            showStatus(data.message || payload.message || '发生错误', 'error');
            break;
        default:
            break;
    }
}

function updateStats(totalIPs) {
    totalIPsEl.textContent = String(totalIPs || 0);
    highRiskIPsEl.textContent = String(countReportsByRisk('high'));
    mediumRiskIPsEl.textContent = String(countReportsByRisk('medium'));
    lowRiskIPsEl.textContent = String(countReportsByRisk('low'));
}

function countReportsByRisk(riskLevel) {
    return latestReports.filter((item) => item.risk_level === riskLevel).length;
}

function renderReports() {
    if (!latestReports.length) {
        reportsContainer.innerHTML = renderEmptyState('暂无数据', '正在等待局域网行为分析结果...');
        return;
    }

    const filteredReports = currentFilter === 'all'
        ? latestReports
        : latestReports.filter((item) => item.risk_level === currentFilter);

    if (!filteredReports.length) {
        reportsContainer.innerHTML = renderEmptyState('No matching data', 'No devices match the current filter');
        return;
    }

    reportsContainer.innerHTML = filteredReports.map((report) => renderIPReport(report)).join('');
}

function renderIPReport(report) {
    const riskLevel = normalizeRiskLevel(report.risk_level);
    const categoryBars = renderCategoryBars(report.category_stats || {});
    const topDomains = renderTopDomains(report.top_domains || []);
    const riskEvents = renderRiskEvents(report.risk_events || []);

    return `
        <div class="ip-report risk-${riskLevel}">
            <div class="ip-header">
                <div class="ip-address">IP 地址 ${escapeHTML(report.ip)}</div>
                <div class="risk-badge ${riskLevel}">风险分: ${escapeHTML(report.risk_score)}</div>
            </div>
            <div class="ip-stats">
                ${renderStat('监控时长', report.duration)}
                ${renderStat('请求总数', report.total_requests)}
                ${renderStat('发送流量', report.total_bytes_sent)}
                ${renderStat('接收流量', report.total_bytes_received)}
                ${renderStat('域名数量', report.unique_domains)}
                ${renderStat('活跃时间', `${report.first_seen || '--'} - ${report.last_seen || '--'}`)}
            </div>
            ${categoryBars ? `<div class="category-breakdown"><h4>分类统计</h4><div class="category-bars">${categoryBars}</div></div>` : ''}
            ${topDomains ? `<div class="top-domains"><h4>高频域名</h4><div class="domain-list">${topDomains}</div></div>` : ''}
            ${riskEvents ? `<div class="top-domains"><h4>风险事件</h4><div class="domain-list">${riskEvents}</div></div>` : ''}
        </div>
    `;
}

function renderCategoryBars(categoryStats) {
    return Object.entries(categoryStats)
        .filter(([, stats]) => Number(stats.count) > 0)
        .sort((a, b) => Number(b[1].percentage) - Number(a[1].percentage))
        .map(([category, stats]) => {
            const percentage = clampPercentage(stats.percentage);
            return `
                <div class="category-bar">
                    <div class="category-label">${escapeHTML(CATEGORY_LABELS[category] || category)}</div>
                    <div class="category-progress">
                        <div class="category-fill" style="width:${percentage}%; background:${CATEGORY_COLORS[category] || CATEGORY_COLORS.unknown}"></div>
                    </div>
                    <div class="category-percentage">${percentage}%</div>
                </div>
            `;
        }).join('');
}

function renderTopDomains(domains) {
    return domains.slice(0, 5).map((domain) => {
        const category = domain.category || 'unknown';
        return `
            <div class="domain-item">
                <div class="domain-name">${escapeHTML(domain.domain)}</div>
                <div class="domain-label" style="background:${CATEGORY_COLORS[category] || CATEGORY_COLORS.unknown}; color:white;">
                    ${escapeHTML(domain.label || CATEGORY_LABELS[category] || category)}
                </div>
                <div class="domain-count">${escapeHTML(domain.count)} 次 | ${escapeHTML(domain.bytes)}</div>
            </div>
        `;
    }).join('');
}

function renderRiskEvents(events) {
    return events.map((event) => `
        <div class="domain-item" style="background:#fee;">
            <div class="domain-name">${escapeHTML(event.domain)}</div>
            <div class="domain-label" style="background:#e74c3c; color:white;">${escapeHTML(event.category)}</div>
            <div class="domain-count">${formatUnix(event.time)}</div>
        </div>
    `).join('');
}

function renderStat(label, value) {
    return `
        <div class="ip-stat">
            <div class="ip-stat-label">${escapeHTML(label)}</div>
            <div class="ip-stat-value">${escapeHTML(value)}</div>
        </div>
    `;
}

function renderEmptyState(title, message) {
    return `
        <div class="no-data">
            <h3>${escapeHTML(title)}</h3>
            <p>${escapeHTML(message)}</p>
        </div>
    `;
}

function showStatus(message, type = 'info') {
    if (statusTimer) {
        clearTimeout(statusTimer);
        statusTimer = null;
    }

    statusMessage.innerHTML = `
        <div class="status-message" style="background:${STATUS_COLORS[type] || STATUS_COLORS.info}">
            ${escapeHTML(message)}
        </div>
    `;

    if (type !== 'monitoring') {
        statusTimer = setTimeout(() => {
            statusMessage.innerHTML = '';
            statusTimer = null;
        }, STATUS_CLEAR_DELAY_MS);
    }
}

function updateUIState() {
    startBtn.disabled = isMonitoring;
    stopBtn.disabled = !isMonitoring;
    interfaceSelect.disabled = isMonitoring;
    threatIntelSelect.disabled = isMonitoring;
}

function restorePreferences() {
    const preferences = loadJSONStorage(
        STORAGE_KEY,
        null,
        (error) => console.error('restore lan preferences failed', error)
    );
    if (!preferences) return;

    if (preferences.interface) interfaceSelect.value = preferences.interface;
    if (preferences.threatIntel) threatIntelSelect.value = preferences.threatIntel;
    if (preferences.filter) {
        currentFilter = preferences.filter;
        document.querySelectorAll('.filter-btn').forEach((item) => {
            item.classList.toggle('active', item.dataset.filter === currentFilter);
        });
    }
}

function persistPreferences() {
    saveJSONStorage(STORAGE_KEY, {
        interface: interfaceSelect.value,
        threatIntel: threatIntelSelect.value,
        filter: currentFilter
    }, (error) => console.error('persist lan preferences failed', error));
}

function normalizeRiskLevel(value) {
    return RISK_LEVELS.has(value) ? value : 'low';
}

function clampPercentage(value) {
    const percentage = Number(value);
    if (!Number.isFinite(percentage)) return 0;
    return Math.min(Math.max(percentage, 0), 100);
}

function formatUnix(value) {
    if (!value) return '--';
    return new Date(value * 1000).toLocaleTimeString();
}

function fallbackEscapeHTML(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function fallbackLoadJSONStorage(key, fallbackValue, onError) {
    try {
        const raw = localStorage.getItem(key);
        if (!raw) {
            return fallbackValue;
        }
        return JSON.parse(raw);
    } catch (error) {
        if (typeof onError === 'function') {
            onError(error);
        }
        return fallbackValue;
    }
}

function fallbackSaveJSONStorage(key, value, onError) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
    } catch (error) {
        if (typeof onError === 'function') {
            onError(error);
        }
        return false;
    }
}
