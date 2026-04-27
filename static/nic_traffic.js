let ws = null;
let chart = null;
let selectedNics = new Set();
let isMonitoring = false;
let isRealtime = true;
let chartData = {};
let reconnectRequested = false;
let pendingStartPayload = null;
const STORAGE_KEY = 'nic_monitor_preferences';
const runtimeClient = window.SecflowTaskRuntime || {};
const createManagedTaskPage = runtimeClient.createManagedTaskPage;
const escapeHTML = runtimeClient.escapeHTML || fallbackEscapeHTML;
const loadJSONStorage = runtimeClient.loadJSONStorage || fallbackLoadJSONStorage;
const saveJSONStorage = runtimeClient.saveJSONStorage || fallbackSaveJSONStorage;
let managedPage = null;

const runtimePollIntervalMs = 1000;

document.addEventListener('DOMContentLoaded', async () => {
    initializeUI();
    setupEventListeners();
    setupManagedPage();
    initChart();
    await loadAvailableNics();
    restorePreferences();
    await restoreRuntime();
    setInterval(requestRealtimeSnapshot, runtimePollIntervalMs);
});

function setupManagedPage() {
    if (!createManagedTaskPage) {
        return;
    }

    managedPage = createManagedTaskPage({
        runtimePath: '/api/runtime/nic-monitor',
        wsPath: '/ws/nic-monitor',
        reconnectMs: 1200,
        onSocketOpen: (_event, socket) => {
            ws = socket;
            addLog('info', 'WebSocket connected');
            updateConnectionStatus(true);
            requestRealtimeSnapshot();
            requestLiveSeries();
        },
        onMessage: handleMessage,
        onError: (_error, context) => {
            if (context && context.phase === 'parse') {
                addLog('error', context.raw);
                return;
            }
            addLog('error', 'WebSocket error');
            updateConnectionStatus(false);
        },
        onSocketClose: () => {
            ws = null;
            updateConnectionStatus(false);
            addLog('info', 'WebSocket closed');
        },
        onReconnect: () => {
            addLog('info', 'Reconnecting WebSocket...');
        }
    });
}

function initializeUI() {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 3600000);
    document.getElementById('endTime').value = formatDateTimeLocal(now);
    document.getElementById('startTime').value = formatDateTimeLocal(oneHourAgo);
}

function setupEventListeners() {
    document.getElementById('btnStart').addEventListener('click', startMonitoring);
    document.getElementById('btnStop').addEventListener('click', stopMonitoring);
    document.getElementById('btnRealtime').addEventListener('click', switchToRealtime);
    document.getElementById('btnHistory').addEventListener('click', switchToHistory);
    document.getElementById('btnLoadHistory').addEventListener('click', loadHistoryData);
    document.getElementById('btnExport').addEventListener('click', exportData);
    document.getElementById('btnClearLog').addEventListener('click', clearLog);
    document.getElementById('metricSelect').addEventListener('change', () => {
        persistPreferences();
        updateChart();
    });
    document.getElementById('timeWindow').addEventListener('change', () => {
        persistPreferences();
        if (isMonitoring && isRealtime) {
            requestLiveSeries();
        }
    });
}

async function loadAvailableNics() {
    try {
        const response = await fetch('/api/nic/list');
        const data = await response.json();
        if (data.success && data.nics) {
            displayNicList(data.nics);
        } else {
            addLog('error', '加载网卡列表失败');
        }
    } catch (error) {
        addLog('error', `加载网卡列表失败: ${error.message}`);
    }
}

function displayNicList(nics) {
    const container = document.getElementById('nicList');
    container.innerHTML = '';

    if (!nics.length) {
        container.innerHTML = '<p class="text-muted">No NICs found</p>';
        return;
    }

    nics.forEach((nic) => {
        const wrapper = document.createElement('div');
        wrapper.className = 'checkbox-item';

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = `nic_${nic.name}`;
        checkbox.value = nic.name;
        checkbox.checked = selectedNics.has(nic.name);
        checkbox.addEventListener('change', (event) => {
            if (event.target.checked) {
                selectedNics.add(nic.name);
            } else {
                selectedNics.delete(nic.name);
            }
            persistPreferences();
        });

        const label = document.createElement('label');
        label.htmlFor = checkbox.id;
        label.textContent = nic.name;

        const info = document.createElement('span');
        info.className = 'nic-info';
        info.textContent = ` (RX: ${formatBytes(nic.bytes_recv)}, TX: ${formatBytes(nic.bytes_sent)})`;

        wrapper.appendChild(checkbox);
        wrapper.appendChild(label);
        label.appendChild(info);
        container.appendChild(wrapper);
    });
}

async function restoreRuntime() {
    try {
        const restoreOptions = {
            onCommand: restoreNICCommand,
            onResume: (runtime) => {
                reconnectRequested = true;
                isMonitoring = true;
                updateStartStopState();
                if (!runtime.active) {
                    updateStatus('Recovering...', 'success');
                }
                updateStatus('Running in background...', 'success');
            }
        };
        if (!managedPage) {
            console.error('managed task runtime client is unavailable');
            return;
        }

        await managedPage.restoreRuntime(restoreOptions);
    } catch (error) {
        addLog('error', `恢复运行状态失败: ${error.message}`);
    }
}

function restoreNICCommand(command) {
    const rawNics = Array.isArray(command.nics) ? command.nics : [];
    selectedNics = new Set(rawNics.filter((nic) => typeof nic === 'string'));
    syncSelectedNicsUI();
    persistPreferences();
}

function syncSelectedNicsUI() {
    selectedNics.forEach((nic) => {
        const checkbox = document.getElementById(`nic_${nic}`);
        if (checkbox) {
            checkbox.checked = true;
        }
    });
}

function startMonitoring() {
    if (!selectedNics.size) {
        addLog('warning', 'Select at least one NIC');
        return;
    }

    persistPreferences();

    pendingStartPayload = {
        action: 'start',
        nics: Array.from(selectedNics)
    };

    reconnectRequested = true;
    isMonitoring = true;
    updateStartStopState();
    updateStatus('正在启动...', 'success');
    if (sendSocketPayload(pendingStartPayload)) {
        pendingStartPayload = null;
        requestRealtimeSnapshot();
        requestLiveSeries();
    }
    ensureSocket();
}

function stopMonitoring() {
    reconnectRequested = false;
    pendingStartPayload = null;

    sendSocketPayload({ action: 'stop' });

    isMonitoring = false;
    updateStartStopState();
    updateConnectionStatus(false);
    updateStatus('Stopped', 'warning');
}

function ensureSocket() {
    if (managedPage) {
        ws = managedPage.ensureSocket();
        return;
    }

    console.error('managed task runtime client is unavailable');
}

function hasOpenSocket() {
    if (managedPage) {
        return !!ws && ws.readyState === WebSocket.OPEN;
    }
    return false;
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

function handleMessage(message) {
    const { type, message: msg } = message;
    const payload = message.payload || {};
    const metricType = payload.metricType || type;
    const data = payload.data || {};

    switch (type) {
        case 'status':
            addLog('info', msg || '运行中');
            break;
        case 'error':
            addLog('error', msg || '发生错误');
            break;
        case 'nic_telemetry':
            if (metricType === 'realtime_data') {
                updateRealtimeData(data || {});
            } else if (metricType === 'live_series') {
                updateChartWithSeries(data || {});
            } else if (metricType === 'history_data') {
                updateChartWithSeries(data || {});
                document.getElementById('statisticsSection').style.display = 'block';
            } else if (metricType === 'statistics') {
                displayStatistics(data || {});
            }
            break;
        default:
            console.log('未知消息类型:', type);
            break;
    }
}

function requestRealtimeSnapshot() {
    if (!isMonitoring || !isRealtime || !hasOpenSocket() || !selectedNics.size) {
        return;
    }

    sendSocketPayload({
        action: 'realtime',
        nics: Array.from(selectedNics)
    });
}

function requestLiveSeries() {
    if (!hasOpenSocket() || !selectedNics.size) {
        return;
    }

    sendSocketPayload({
        action: 'live_series',
        nics: Array.from(selectedNics),
        seconds: parseInt(document.getElementById('timeWindow').value, 10)
    });
}

function updateRealtimeData(data) {
    const container = document.getElementById('realtimeCards');
    const presentNics = new Set(Object.keys(data));

    Object.keys(data).forEach((nic) => {
        const nicData = data[nic];
        let card = document.getElementById(`card_${nic}`);

        if (!card) {
            card = createRealtimeCard(nic);
            container.appendChild(card);
        }

        card.querySelector('.rx-value').textContent = formatBps(nicData.rx_bps);
        card.querySelector('.tx-value').textContent = formatBps(nicData.tx_bps);
        card.querySelector('.total-value').textContent = formatBps(nicData.total_bps);
        card.querySelector('.timestamp').textContent = formatTimestamp(nicData.timestamp);

        if (!chartData[nic]) {
            chartData[nic] = [];
        }

        chartData[nic].push({
            ts: nicData.timestamp,
            rx_bps: nicData.rx_bps,
            tx_bps: nicData.tx_bps,
            total_bps: nicData.total_bps
        });

        if (chartData[nic].length > 600) {
            chartData[nic].shift();
        }
    });

    Array.from(container.children).forEach((child) => {
        const nic = child.id.replace('card_', '');
        if (!presentNics.has(nic)) {
            child.remove();
        }
    });

    updateChart();
}

function createRealtimeCard(nic) {
    const card = document.createElement('div');
    card.id = `card_${nic}`;
    card.className = 'realtime-card';
    card.innerHTML = `
        <div class="card-title">${escapeHTML(nic)}</div>
        <div class="metric-row"><span class="metric-label">接收速率 (RX):</span><span class="metric-value rx-value">0 bps</span></div>
        <div class="metric-row"><span class="metric-label">发送速率 (TX):</span><span class="metric-value tx-value">0 bps</span></div>
        <div class="metric-row"><span class="metric-label">总速率:</span><span class="metric-value total-value">0 bps</span></div>
        <div class="timestamp">--</div>
    `;
    return card;
}

function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    chart = new Chart(ctx, {
        type: 'line',
        data: { datasets: [] },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { position: 'top' },
                tooltip: {
                    callbacks: {
                        label(context) {
                            return `${context.dataset.label || ''}: ${formatBps(context.parsed.y)}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    type: 'time',
                    time: {
                        unit: 'minute',
                        displayFormats: { minute: 'HH:mm' }
                    },
                    title: { display: true, text: '时间' }
                },
                y: {
                    beginAtZero: true,
                    title: { display: true, text: '速率 (bps)' },
                    ticks: {
                        callback(value) {
                            return formatBps(value);
                        }
                    }
                }
            }
        }
    });
}

function updateChart() {
    if (!chart) return;

    const metric = document.getElementById('metricSelect').value;
    const colors = [
        { border: 'rgb(75, 192, 192)', bg: 'rgba(75, 192, 192, 0.1)' },
        { border: 'rgb(255, 99, 132)', bg: 'rgba(255, 99, 132, 0.1)' },
        { border: 'rgb(54, 162, 235)', bg: 'rgba(54, 162, 235, 0.1)' },
        { border: 'rgb(255, 206, 86)', bg: 'rgba(255, 206, 86, 0.1)' },
        { border: 'rgb(153, 102, 255)', bg: 'rgba(153, 102, 255, 0.1)' }
    ];

    let colorIndex = 0;
    const datasets = [];

    Object.keys(chartData).forEach((nic) => {
        const data = chartData[nic] || [];
        const color = colors[colorIndex % colors.length];

        if (metric === 'total') {
            datasets.push(buildDataset(`${nic} - Total`, data, 'total_bps', color));
            colorIndex += 1;
        } else if (metric === 'rx') {
            datasets.push(buildDataset(`${nic} - RX`, data, 'rx_bps', color));
            colorIndex += 1;
        } else if (metric === 'tx') {
            datasets.push(buildDataset(`${nic} - TX`, data, 'tx_bps', color));
            colorIndex += 1;
        } else {
            const rxColor = colors[colorIndex % colors.length];
            colorIndex += 1;
            const txColor = colors[colorIndex % colors.length];
            colorIndex += 1;
            datasets.push(buildDataset(`${nic} - RX`, data, 'rx_bps', rxColor));
            datasets.push(buildDataset(`${nic} - TX`, data, 'tx_bps', txColor));
        }
    });

    chart.data.datasets = datasets;
    chart.update('none');
}

function buildDataset(label, data, field, color) {
    return {
        label,
        data: data.map((point) => ({ x: point.ts * 1000, y: point[field] })),
        borderColor: color.border,
        backgroundColor: color.bg,
        tension: 0.1,
        fill: true
    };
}

function updateChartWithSeries(data) {
    chartData = data || {};
    updateChart();
}

function switchToRealtime() {
    isRealtime = true;
    document.getElementById('btnRealtime').classList.add('active');
    document.getElementById('btnHistory').classList.remove('active');
    document.getElementById('historyControls').style.display = 'none';
    document.getElementById('statisticsSection').style.display = 'none';
    persistPreferences();
    requestLiveSeries();
}

function switchToHistory() {
    isRealtime = false;
    document.getElementById('btnHistory').classList.add('active');
    document.getElementById('btnRealtime').classList.remove('active');
    document.getElementById('historyControls').style.display = 'block';
    persistPreferences();
}

function loadHistoryData() {
    if (!hasOpenSocket()) {
        addLog('error', 'Start monitoring first');
        return;
    }

    if (!selectedNics.size) {
        addLog('warning', '请选择网卡');
        return;
    }

    const startTime = document.getElementById('startTime').value;
    const endTime = document.getElementById('endTime').value;
    persistPreferences();
    if (!startTime || !endTime) {
        addLog('warning', '请选择时间范围');
        return;
    }

    const startTs = Math.floor(new Date(startTime).getTime() / 1000);
    const endTs = Math.floor(new Date(endTime).getTime() / 1000);
    if (startTs >= endTs) {
        addLog('warning', 'Start time must be before end time');
        return;
    }

    sendSocketPayload({ action: 'history', nics: Array.from(selectedNics), start_ts: startTs, end_ts: endTs });
    sendSocketPayload({ action: 'statistics', nics: Array.from(selectedNics), start_ts: startTs, end_ts: endTs });
    addLog('info', '正在加载历史数据...');
}

function displayStatistics(stats) {
    const container = document.getElementById('statisticsContent');
    container.innerHTML = '';

    Object.keys(stats).forEach((nic) => {
        const nicStats = stats[nic];
        const card = document.createElement('div');
        card.className = 'statistics-card';
        card.innerHTML = `
            <h4>${escapeHTML(nic)}</h4>
            <div class="stats-grid">
                <div class="stat-item"><div class="stat-label">接收流量 (RX)</div><div class="stat-values"><div>峰值: ${formatBps(nicStats.rx.max)}</div><div>均值: ${formatBps(nicStats.rx.avg)}</div><div>总量: ${formatBytes(nicStats.rx.total_bytes)}</div></div></div>
                <div class="stat-item"><div class="stat-label">发送流量 (TX)</div><div class="stat-values"><div>峰值: ${formatBps(nicStats.tx.max)}</div><div>均值: ${formatBps(nicStats.tx.avg)}</div><div>总量: ${formatBytes(nicStats.tx.total_bytes)}</div></div></div>
                <div class="stat-item"><div class="stat-label">总流量</div><div class="stat-values"><div>峰值: ${formatBps(nicStats.total.max)}</div><div>均值: ${formatBps(nicStats.total.avg)}</div><div>总量: ${formatBytes(nicStats.total.total_bytes)}</div></div></div>
                <div class="stat-item"><div class="stat-label">采样数</div><div class="stat-values"><div>${nicStats.sample_count}</div></div></div>
            </div>
        `;
        container.appendChild(card);
    });
}

function exportData() {
    if (!Object.keys(chartData).length) {
        addLog('warning', '暂无可导出的数据');
        return;
    }

    let csv = 'Timestamp,NIC,RX (bps),TX (bps),Total (bps)\n';
    Object.keys(chartData).forEach((nic) => {
        chartData[nic].forEach((point) => {
            csv += `${new Date(point.ts * 1000).toISOString()},${nic},${point.rx_bps},${point.tx_bps},${point.total_bps}\n`;
        });
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `nic_traffic_${Date.now()}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
    addLog('info', 'Data exported');
}

function formatBps(bps) {
    const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    let value = Number(bps || 0);
    let unitIndex = 0;
    while (value >= 1000 && unitIndex < units.length - 1) {
        value /= 1000;
        unitIndex += 1;
    }
    return `${value.toFixed(2)} ${units[unitIndex]}`;
}

function formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = Number(bytes || 0);
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex += 1;
    }
    return `${value.toFixed(2)} ${units[unitIndex]}`;
}

function formatTimestamp(ts) {
    return new Date(ts * 1000).toLocaleString('zh-CN');
}

function formatDateTimeLocal(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${year}-${month}-${day}T${hours}:${minutes}`;
}

function updateStatus(text, type) {
    const statusText = document.getElementById('statusText');
    statusText.textContent = text;
    statusText.className = `status-${type}`;
}

function updateConnectionStatus(connected) {
    const status = document.getElementById('connectionStatus');
    if (connected) {
        status.textContent = 'Connected';
        status.className = 'status-connected';
    } else {
        status.textContent = 'Disconnected';
        status.className = 'status-disconnected';
    }
}

function updateStartStopState() {
    document.getElementById('btnStart').disabled = isMonitoring;
    document.getElementById('btnStop').disabled = !isMonitoring;
    document.querySelectorAll('#nicList input[type="checkbox"]').forEach((checkbox) => {
        checkbox.disabled = isMonitoring;
    });
}

function addLog(level, message) {
    const logOutput = document.getElementById('logOutput');
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry log-${level}`;
    logEntry.textContent = `[${new Date().toLocaleTimeString('zh-CN')}] [${level.toUpperCase()}] ${message}`;
    logOutput.appendChild(logEntry);
    logOutput.scrollTop = logOutput.scrollHeight;
}

function clearLog() {
    document.getElementById('logOutput').innerHTML = '';
}

function restorePreferences() {
    const preferences = loadJSONStorage(
        STORAGE_KEY,
        {},
        (error) => addLog('error', `读取本地配置失败: ${error.message}`)
    );
    if (Array.isArray(preferences.nics)) {
        selectedNics = new Set(preferences.nics);
        syncSelectedNICCheckboxes();
    }
    if (preferences.metric) document.getElementById('metricSelect').value = preferences.metric;
    if (preferences.timeWindow) document.getElementById('timeWindow').value = preferences.timeWindow;
    if (preferences.mode === 'history') {
        switchToHistory();
    }
    if (preferences.startTime) document.getElementById('startTime').value = preferences.startTime;
    if (preferences.endTime) document.getElementById('endTime').value = preferences.endTime;
}

function persistPreferences() {
    saveJSONStorage(STORAGE_KEY, {
        nics: Array.from(selectedNics),
        metric: document.getElementById('metricSelect').value,
        timeWindow: document.getElementById('timeWindow').value,
        mode: isRealtime ? 'realtime' : 'history',
        startTime: document.getElementById('startTime').value,
        endTime: document.getElementById('endTime').value
    }, (error) => addLog('error', `保存网卡配置失败: ${error.message}`));
}

function syncSelectedNICCheckboxes() {
    document.querySelectorAll('#nicList input[type="checkbox"]').forEach((checkbox) => {
        checkbox.checked = selectedNics.has(checkbox.value);
    });
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
