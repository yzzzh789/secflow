let ws = null;
let reconnectTimer = null;
let availableNICs = [];
let monitoringNICs = new Set();
let trafficData = {};
let trafficWarningThresholds = {};
let latestNICMetrics = {};
let thresholdConfig = null;
let stopConfirmationTimer = null;
let stopConfirmationInFlight = false;
const maxDataPoints = 60;
const runtimeClient = window.SecflowTaskRuntime || {};
const createManagedTaskPage = runtimeClient.createManagedTaskPage;
const escapeHtml = runtimeClient.escapeHTML || fallbackEscapeHtml;
let managedPage = null;

const TEXT = {
    selectNic: "请至少选择一张网卡。",
    loadNicFail: "加载网卡列表失败",
    noNic: "未找到网卡",
    monitoring: "监控中",
    noAlert: "暂无告警",
    noData: "暂无监控数据",
    currentTraffic: "当前流量",
    warningThreshold: "告警阈值",
    criticalThreshold: "严重阈值",
    median: "中位数",
    sampleCount: "样本数",
    state: "状态",
    warmupLeft: "预热剩余",
    second: "秒",
    dynamicThreshold: "动态阈值",
    warmupGuard: "预热保护",
    normal: "正常",
    warning: "告警",
    critical: "严重",
    recovery: "恢复",
    connected: "已连接",
    disconnected: "连接断开"
};

const ctx = document.getElementById("trafficChart").getContext("2d");
const chart = new Chart(ctx, {
    type: "line",
    data: {
        labels: [],
        datasets: []
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
            legend: {
                labels: {
                    color: "#4b5563",
                    filter: (item, chartData) => {
                        const dataset = chartData.datasets[item.datasetIndex];
                        return !dataset?.legendHidden;
                    }
                }
            }
        },
        scales: {
            x: {
                ticks: { color: "#6b7280", maxTicksLimit: 10 },
                grid: { color: "#e5e7eb" }
            },
            y: {
                ticks: {
                    color: "#6b7280",
                    callback: (value) => value.toFixed(2) + " MB/s"
                },
                grid: { color: "#e5e7eb" }
            }
        }
    }
});

function handleSocketOpen() {
    updateStatus(true);
    clearTimeout(reconnectTimer);
    restoreRuntime();
    requestThresholds();
    startPolling();
}

function handleSocketError(error, context) {
    if (context && context.phase === "parse") {
        console.error("WebSocket message handling failed:", error, context.raw);
        return;
    }
    updateStatus(false);
}

function handleSocketClose() {
    updateStatus(false);
    stopPolling();
}

function setupManagedPage() {
    if (!createManagedTaskPage || managedPage) {
        return;
    }

    managedPage = createManagedTaskPage({
        runtimePath: "/api/runtime/nic-monitor",
        wsPath: "/ws/nic-monitor",
        reconnectMs: 5000,
        onSocketOpen: (_event, activeSocket) => {
            ws = activeSocket;
            handleSocketOpen();
        },
        onMessage: handleMessage,
        onError: handleSocketError,
        onSocketClose: () => {
            ws = null;
            handleSocketClose();
        }
    });
    managedPage.setReconnectRequested(true);
}

function connectWebSocket() {
    setupManagedPage();
    if (managedPage) {
        ws = managedPage.ensureSocket();
        return;
    }

    console.error("managed task runtime client is unavailable");
}

function handleMessage(data) {
    switch (data.type) {
        case "nic_telemetry":
            if (data.payload?.metricType === "realtime_data") {
                updateTrafficData(data.payload.data || {});
            } else if (data.payload?.metricType === "live_series") {
                updateTrafficSeries(data.payload.data || {});
            }
            break;
        case "alert":
            showAlert(data.payload?.data || data.data || {});
            break;
        case "thresholds":
            thresholdConfig = data.payload?.data || data.data || null;
            renderThresholdList();
            break;
        case "error":
            console.error(data.message);
            break;
        default:
            break;
    }
}

async function loadNICList() {
    try {
        const response = await fetch("/api/nic/list");
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        if (!data.success || !Array.isArray(data.nics)) {
            throw new Error(data.error || TEXT.loadNicFail);
        }
        availableNICs = data.nics || [];
        renderNICList();
    } catch (error) {
        console.error(error);
        document.getElementById("nicList").innerHTML =
            `<div class="empty-state">${TEXT.loadNicFail}</div>`;
    }
}

async function restoreRuntime() {
    try {
        if (!managedPage) {
            console.error("managed task runtime client is unavailable");
            return;
        }

        await managedPage.restoreRuntime({
            onInactive: () => {
                clearMonitoringState();
            },
            onCommand: (command) => {
                const nics = Array.isArray(command.nics)
                    ? command.nics.filter((nic) => typeof nic === "string")
                    : [];
                if (nics.length > 0) {
                    monitoringNICs = new Set(nics);
                    renderNICList();
                    updateMonitoringCount();
                    requestRealtimeSnapshot();
                    requestLiveSeries();
                    return;
                }
                clearMonitoringState();
            }
        });
    } catch (error) {
        console.error("restore runtime failed:", error);
    }
}

function renderNICList() {
    const container = document.getElementById("nicList");
    if (availableNICs.length === 0) {
        container.innerHTML = `<div class="empty-state">${TEXT.noNic}</div>`;
        return;
    }

    container.innerHTML = availableNICs.map((nic) => {
        const isMonitoring = monitoringNICs.has(nic.name);
        const displayName = nic.displayName || nic.name;
        const secondaryName = displayName !== nic.name ? `<div class="nic-status">${escapeHtml(nic.name)}</div>` : "";
        return `
            <div class="nic-item ${isMonitoring ? "monitoring" : ""}"
                 onclick="toggleNIC('${escapeForAttr(nic.name)}')">
                <input type="checkbox"
                       class="nic-checkbox"
                       id="nic_${escapeForId(nic.name)}"
                       ${isMonitoring ? "checked" : ""}
                       onclick="event.stopPropagation()">
                <div class="nic-name">${escapeHtml(displayName)}</div>
                ${secondaryName}
                ${isMonitoring ? `<div class="nic-status">${TEXT.monitoring}</div>` : ""}
            </div>
        `;
    }).join("");
}

function escapeForAttr(value) {
    return String(value).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function escapeForId(value) {
    return String(value).replace(/[^a-zA-Z0-9_-]/g, "_");
}

function fallbackEscapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function getNicCheckboxId(nicName) {
    return `nic_${escapeForId(nicName)}`;
}

function toggleNIC(nicName) {
    const checkbox = document.getElementById(getNicCheckboxId(nicName));
    if (checkbox) {
        checkbox.checked = !checkbox.checked;
    }
}

function getSelectedNICs() {
    return availableNICs
        .filter((nic) => document.getElementById(getNicCheckboxId(nic.name))?.checked)
        .map((nic) => nic.name);
}

function hasOpenSocket() {
    if (managedPage) {
        return !!ws && ws.readyState === WebSocket.OPEN;
    }
    return false;
}

function sendSocketPayload(payload) {
    if (managedPage) {
        if (payload && payload.action === "start") {
            return managedPage.start(payload);
        }
        if (payload && payload.action === "stop") {
            return managedPage.stop(payload);
        }
        return managedPage.send(payload);
    }

    console.error("managed task runtime client is unavailable");
    return false;
}

function startMonitoring() {
    const selected = getSelectedNICs();
    if (selected.length === 0) {
        alert(TEXT.selectNic);
        return;
    }

    if (!hasOpenSocket()) {
        console.error("WebSocket is not ready.");
        return;
    }

    monitoringNICs = new Set(selected);
    renderNICList();
    updateMonitoringCount();

    sendSocketPayload({
        action: "start",
        nics: selected
    });
}

function stopAll() {
    if (!hasOpenSocket()) {
        return;
    }

    sendSocketPayload({ action: "stop" });
    startStopConfirmationPolling();
}

function requestThresholds() {
    if (!hasOpenSocket()) {
        return;
    }
    sendSocketPayload({ action: "get_thresholds" });
}

async function syncRuntimeState() {
    try {
        const response = await fetch("/api/runtime/nic-monitor");
        if (!response.ok) {
            return null;
        }
        return await response.json();
    } catch (error) {
        console.error("sync runtime state failed:", error);
        return null;
    }
}

function startStopConfirmationPolling() {
    stopStopConfirmationPolling();
    let attempts = 0;
    stopConfirmationTimer = setInterval(async () => {
        if (stopConfirmationInFlight) {
            return;
        }
        stopConfirmationInFlight = true;
        attempts += 1;
        try {
            const runtime = await syncRuntimeState();
            if (runtime && !runtime.active && runtime.desiredState !== "running") {
                stopStopConfirmationPolling();
                clearMonitoringState();
                return;
            }
            if (attempts >= 12) {
                stopStopConfirmationPolling();
                if (runtime) {
                    showAlert({
                        level: "warning",
                        state: "stop_pending",
                        message: "停止命令已发送，但后端仍显示监控在运行，当前界面状态已保留。"
                    });
                    requestRealtimeSnapshot();
                    requestLiveSeries();
                    return;
                }
                showAlert({
                    level: "warning",
                    state: "stop_pending",
                    message: "停止命令已发送，但暂时无法确认后端状态，当前界面状态已保留。"
                });
            }
        } finally {
            stopConfirmationInFlight = false;
        }
    }, 500);
}

function stopStopConfirmationPolling() {
    if (stopConfirmationTimer) {
        clearInterval(stopConfirmationTimer);
        stopConfirmationTimer = null;
    }
    stopConfirmationInFlight = false;
}

function clearMonitoringState() {
    stopStopConfirmationPolling();
    monitoringNICs = new Set();
    latestNICMetrics = {};
    trafficData = {};
    trafficWarningThresholds = {};
    renderNICList();
    updateMonitoringCount();
    updateChartDatasets();
    updateChart();
    renderThresholdList();
    document.getElementById("totalTraffic").textContent = "0.00";
    document.getElementById("peakTraffic").textContent = "0.00";
    document.getElementById("avgTraffic").textContent = "0.00";
}

function requestRealtimeSnapshot() {
    if (!hasOpenSocket() || monitoringNICs.size === 0) {
        return;
    }
    sendSocketPayload({
        action: "realtime",
        nics: Array.from(monitoringNICs)
    });
}

function requestLiveSeries() {
    if (!hasOpenSocket() || monitoringNICs.size === 0) {
        return;
    }
    sendSocketPayload({
        action: "live_series",
        nics: Array.from(monitoringNICs),
        seconds: maxDataPoints
    });
}

function startPolling() {
    stopPolling();
    window.__trafficRealtimeTimer = setInterval(requestRealtimeSnapshot, 1000);
    window.__trafficSeriesTimer = setInterval(requestLiveSeries, 5000);
}

function stopPolling() {
    if (window.__trafficRealtimeTimer) {
        clearInterval(window.__trafficRealtimeTimer);
        window.__trafficRealtimeTimer = null;
    }
    if (window.__trafficSeriesTimer) {
        clearInterval(window.__trafficSeriesTimer);
        window.__trafficSeriesTimer = null;
    }
}

function updateMonitoringCount() {
    document.getElementById("monitoringCount").textContent = monitoringNICs.size;
}

function getChartNicNames() {
    const names = new Set(Array.from(monitoringNICs));
    Object.keys(latestNICMetrics).forEach((name) => names.add(name));
    Object.keys(trafficData)
        .filter((key) => key !== "labels")
        .forEach((name) => names.add(name));
    return Array.from(names);
}

function updateTrafficData(data) {
    const now = new Date().toLocaleTimeString("zh-CN", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });

    if (!trafficData.labels) {
        trafficData.labels = [];
    }
    trafficData.labels.push(now);
    if (trafficData.labels.length > maxDataPoints) {
        trafficData.labels.shift();
    }

    let totalTraffic = 0;
    let monitoringStateChanged = false;
    for (const [nicName, nicData] of Object.entries(data)) {
        if (!nicData || typeof nicData !== "object") {
            continue;
        }

        if (!monitoringNICs.has(nicName)) {
            monitoringNICs.add(nicName);
            monitoringStateChanged = true;
        }

        if (!trafficData[nicName]) {
            trafficData[nicName] = [];
        }
        if (!trafficWarningThresholds[nicName]) {
            trafficWarningThresholds[nicName] = [];
        }

        const mbps = Number.isFinite(nicData.total_mbps) ? nicData.total_mbps : 0;
        trafficData[nicName].push(mbps);
        trafficWarningThresholds[nicName].push(getChartThresholdMbps(nicData));
        latestNICMetrics[nicName] = nicData;
        totalTraffic += mbps;

        if (trafficData[nicName].length > maxDataPoints) {
            trafficData[nicName].shift();
        }
        if (trafficWarningThresholds[nicName].length > maxDataPoints) {
            trafficWarningThresholds[nicName].shift();
        }
    }

    if (monitoringStateChanged) {
        renderNICList();
        updateMonitoringCount();
    }

    updateChartDatasets();
    updateChart();
    renderThresholdList();
    document.getElementById("totalTraffic").textContent = totalTraffic.toFixed(2);

    const allValues = Object.entries(trafficData)
        .filter(([key, arr]) => key !== "labels" && Array.isArray(arr))
        .flatMap(([, arr]) => arr)
        .filter((value) => Number.isFinite(value));

    if (allValues.length > 0) {
        const peak = Math.max(...allValues);
        const avg = allValues.reduce((a, b) => a + b, 0) / allValues.length;
        document.getElementById("peakTraffic").textContent = peak.toFixed(2);
        document.getElementById("avgTraffic").textContent = avg.toFixed(2);
    } else {
        document.getElementById("peakTraffic").textContent = "0.00";
        document.getElementById("avgTraffic").textContent = "0.00";
    }
}

function updateTrafficSeries(data) {
    let longestLabels = [];

    for (const [nicName, points] of Object.entries(data)) {
        if (!Array.isArray(points)) {
            continue;
        }

        trafficData[nicName] = points.map((point) => (Number(point.total_bps) || 0) / 1024 / 1024);
        trafficWarningThresholds[nicName] = points.map((point) => getChartThresholdMbps(point));

        if (points.length > longestLabels.length) {
            longestLabels = points.map((point) => formatSeriesTime(point.ts));
        }
    }

    if (longestLabels.length > 0) {
        trafficData.labels = longestLabels.slice(-maxDataPoints);
    }

    updateChartDatasets();
    updateChart();
}

function updateChartDatasets() {
    const trafficColors = [
        "#16a34a", "#15803d", "#059669", "#0f766e",
        "#0284c7", "#2563eb", "#7c3aed", "#ca8a04"
    ];

    const datasetMap = new Map(
        (chart.data.datasets || []).map((dataset) => [dataset.datasetKey, dataset])
    );
    const nextDatasets = [];

    getChartNicNames().forEach((nic, index) => {
        const trafficColor = trafficColors[index % trafficColors.length];
        const values = [...(trafficData[nic] || [])];
        const thresholds = [...(trafficWarningThresholds[nic] || [])];
        const trafficKey = `${nic}::traffic`;
        const thresholdKey = `${nic}::threshold`;

        const trafficDataset = datasetMap.get(trafficKey) || {};
        trafficDataset.datasetKey = trafficKey;
        trafficDataset.label = `${nic} traffic`;
        trafficDataset.data = values;
        trafficDataset.borderColor = trafficColor;
        trafficDataset.backgroundColor = trafficColor + "20";
        trafficDataset.tension = 0.35;
        trafficDataset.fill = false;
        trafficDataset.borderWidth = 2;
        trafficDataset.pointRadius = 2;
        trafficDataset.pointHoverRadius = 4;
        trafficDataset.showLine = true;
        trafficDataset.spanGaps = false;
        trafficDataset.pointBackgroundColor = trafficColor;
        trafficDataset.pointBorderColor = trafficColor;
        trafficDataset.legendHidden = false;

        const thresholdDataset = datasetMap.get(thresholdKey) || {};
        thresholdDataset.datasetKey = thresholdKey;
        thresholdDataset.label = `${nic} threshold`;
        thresholdDataset.data = thresholds;
        thresholdDataset.borderColor = "#ef4444";
        thresholdDataset.backgroundColor = "#ef444420";
        thresholdDataset.tension = 0;
        thresholdDataset.fill = false;
        thresholdDataset.borderWidth = 2;
        thresholdDataset.pointRadius = 0;
        thresholdDataset.pointHoverRadius = 3;
        thresholdDataset.showLine = true;
        thresholdDataset.spanGaps = true;
        thresholdDataset.pointBackgroundColor = "#ef4444";
        thresholdDataset.pointBorderColor = "#ef4444";
        thresholdDataset.legendHidden = false;

        nextDatasets.push(trafficDataset, thresholdDataset);
    });

    chart.data.datasets = nextDatasets;
}

function updateChart() {
    chart.data.labels = [...(trafficData.labels || [])];
    try {
        chart.update();
    } catch (error) {
        console.error("Chart update failed:", error);
    }
}

function getChartThresholdMbps(nicData) {
    const thresholds = nicData?.thresholds || {};
    const isWarmup = Number.isFinite(thresholds.warmup_remaining_s) &&
        thresholds.warmup_remaining_s > 0;
    if (isWarmup) {
        if (Number.isFinite(thresholds.fixed_critical_mbps)) {
            return thresholds.fixed_critical_mbps;
        }
        if (Number.isFinite(thresholds.critical_mbps)) {
            return thresholds.critical_mbps;
        }
    }
    if (Number.isFinite(thresholds.warning_mbps)) {
        return thresholds.warning_mbps;
    }
    if (Number.isFinite(thresholds.fixed_warning_mbps)) {
        return thresholds.fixed_warning_mbps;
    }
    return null;
}

function _legacyFormatWarmupTextSafe(thresholds) {
    if (!Number.isFinite(thresholds?.warmup_remaining_s) || thresholds.warmup_remaining_s <= 0) {
        return "";
    }
    return `，${TEXT.warmupLeft} ${thresholds.warmup_remaining_s} ${TEXT.second}`;
}

function showAlert(alert) {
    const container = document.getElementById("alertContainer");
    const emptyState = container.querySelector(".empty-state");
    if (emptyState) {
        emptyState.remove();
    }

    const level = alert.level || "warning";
    const icon = alert.state === "recovery" ? "OK" : (level === "critical" ? "!!" : "!");
    const nicPrefix = alert.nic ? `[${escapeHtml(alert.nic)}] ` : "";

    const alertDiv = document.createElement("div");
    alertDiv.className = `alert ${level}`;
    alertDiv.innerHTML = `
        <div>${icon}</div>
        <div class="alert-content">${nicPrefix}${escapeHtml(alert.message || "")}</div>
        <div class="alert-close" onclick="this.parentElement.remove()">x</div>
    `;

    container.insertBefore(alertDiv, container.firstChild);

    while (container.children.length > 6) {
        container.lastChild.remove();
    }

    setTimeout(() => {
        if (alertDiv.parentElement) {
            alertDiv.remove();
        }
    }, 12000);
}

function formatWarmupTextSafe(thresholds) {
    if (!Number.isFinite(thresholds?.warmup_remaining_s) || thresholds.warmup_remaining_s <= 0) {
        return "";
    }
    return `，${TEXT.warmupLeft} ${thresholds.warmup_remaining_s} ${TEXT.second}`;
}

function renderThresholdList() {
    const container = document.getElementById("thresholdList");
    const names = Array.from(monitoringNICs).filter((name) => latestNICMetrics[name]);

    if (names.length === 0 && thresholdConfig) {
        container.innerHTML = `
            <div class="threshold-item">
                <div class="threshold-header">
                    <div class="threshold-name">全局阈值配置</div>
                    <div class="threshold-mode">${TEXT.dynamicThreshold}</div>
                </div>
                <div class="threshold-grid">
                    <div>${TEXT.warningThreshold}: ${formatMbps(thresholdConfig.warning_mbps)}</div>
                    <div>${TEXT.criticalThreshold}: ${formatMbps(thresholdConfig.critical_mbps)}</div>
                    <div>${TEXT.warmupLeft}: ${Number.isFinite(thresholdConfig.warmup_seconds) ? thresholdConfig.warmup_seconds : 0} ${TEXT.second}</div>
                    <div>${TEXT.sampleCount}: ${thresholdConfig.min_baseline_samples || 0}</div>
                </div>
            </div>
        `;
        return;
    }

    if (names.length === 0) {
        if (thresholdConfig) {
            container.innerHTML = `
                <div class="threshold-item">
                    <div class="threshold-header">
                        <div class="threshold-name">全局阈值配置</div>
                        <div class="threshold-mode">${TEXT.dynamicThreshold}</div>
                    </div>
                    <div class="threshold-grid">
                        <div>${TEXT.warningThreshold}: ${formatMbps(thresholdConfig.warning_mbps)}</div>
                        <div>${TEXT.criticalThreshold}: ${formatMbps(thresholdConfig.critical_mbps)}</div>
                        <div>${TEXT.warmupLeft}: ${Number.isFinite(thresholdConfig.warmup_seconds) ? thresholdConfig.warmup_seconds : 0} ${TEXT.second}</div>
                        <div>${TEXT.sampleCount}: ${thresholdConfig.min_baseline_samples || 0}</div>
                    </div>
                </div>
            `;
            return;
        }
        container.innerHTML = `<div class="empty-state">${TEXT.noData}</div>`;
        return;
    }

    container.innerHTML = names.map((name) => {
        const nicData = latestNICMetrics[name];
        const thresholds = nicData.thresholds || {};
        const baseline = nicData.baseline || {};
        const alertState = nicData.alert_state || {};
        const mode = thresholds.alerting_mode || "dynamic";

        return `
            <div class="threshold-item">
                <div class="threshold-header">
                    <div class="threshold-name">${escapeHtml(name)}</div>
                    <div class="threshold-mode">${translateAlertMode(mode)}${formatWarmupTextSafe(thresholds)}</div>
                </div>
                <div class="threshold-grid">
                    <div>${TEXT.currentTraffic}: ${formatMbps(nicData.total_mbps)}</div>
                    <div>${TEXT.warningThreshold}: ${formatMbps(thresholds.warning_mbps)}</div>
                    <div>${TEXT.criticalThreshold}: ${formatMbps(thresholds.critical_mbps)}</div>
                    <div>${TEXT.median}: ${formatMbps(baseline.median_mbps)}</div>
                    <div>P95: ${formatMbps(baseline.p95_mbps)}</div>
                    <div>MAD: ${formatMbps(baseline.mad_mbps)}</div>
                    <div>${TEXT.sampleCount}: ${baseline.sample_count || 0}</div>
                    <div>${TEXT.state}: ${translateAlertState(alertState.level || "normal")}</div>
                </div>
            </div>
        `;
    }).join("");
}

function formatMbps(value) {
    return `${Number.isFinite(value) ? value.toFixed(2) : "0.00"} MB/s`;
}

function translateAlertState(state) {
    switch (state) {
        case "warning":
            return TEXT.warning;
        case "critical":
            return TEXT.critical;
        case "recovery":
            return TEXT.recovery;
        default:
            return TEXT.normal;
    }
}

function translateAlertMode(mode) {
    switch (mode) {
        case "fixed_critical_only":
            return TEXT.warmupGuard;
        default:
            return TEXT.dynamicThreshold;
    }
}

function updateStatus(connected) {
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");

    if (connected) {
        dot.className = "status-dot connected";
        text.textContent = TEXT.connected;
    } else {
        dot.className = "status-dot disconnected";
        text.textContent = TEXT.disconnected;
    }
}

function formatSeriesTime(ts) {
    if (!ts) {
        return "";
    }
    return new Date(Number(ts) * 1000).toLocaleTimeString("zh-CN", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
}

window.startMonitoring = startMonitoring;
window.stopAll = stopAll;
window.toggleNIC = toggleNIC;

window.onload = async () => {
    await loadNICList();
    connectWebSocket();
};
