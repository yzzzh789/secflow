const STORAGE_KEYS = {
    ai: 'ai_settings',
    threat: 'threat_capture_preferences',
    behavior: 'behavior_analysis_preferences',
    lan: 'lan_monitor_preferences',
    nic: 'nic_monitor_preferences'
};

const TASK_CONFIG = {
    threat: {
        runtimeUrl: '/api/runtime/threat',
        controlUrl: '/api/task/threat',
        runtimeEl: 'taskRuntimeThreat',
        startButton: 'taskThreatStart',
        stopButton: 'taskThreatStop'
    },
    behavior: {
        runtimeUrl: '/api/runtime/behavior',
        controlUrl: '/api/task/behavior',
        runtimeEl: 'taskRuntimeBehavior',
        startButton: 'taskBehaviorStart',
        stopButton: 'taskBehaviorStop'
    },
    lan: {
        runtimeUrl: '/api/runtime/lan-monitor',
        controlUrl: '/api/task/lan-monitor',
        runtimeEl: 'taskRuntimeLan',
        startButton: 'taskLanStart',
        stopButton: 'taskLanStop'
    },
    nic: {
        runtimeUrl: '/api/runtime/nic-monitor',
        controlUrl: '/api/task/nic-monitor',
        runtimeEl: 'taskRuntimeNic',
        startButton: 'taskNicStart',
        stopButton: 'taskNicStop'
    }
};

const TASK_CENTER_INTERFACE_IDS = ['taskThreatInterface', 'taskBehaviorInterface', 'taskLanInterface'];
let interfaceOptionsLoaded = false;
let nicOptionsLoaded = false;
let taskCenterDataPromise = null;

document.addEventListener('DOMContentLoaded', async () => {
    prepareTaskCenterPlaceholders();
    bindTaskCenterEvents();
    restoreTaskPreferences();
    scheduleTaskCenterLazyLoad();
    await loadOverview();
    loadTaskRuntimes();

    setInterval(() => {
        if (!document.hidden) {
            refreshAll();
        }
    }, 5000);
});

async function refreshAll() {
    await Promise.all([
        loadOverview(),
        loadTaskRuntimes()
    ]);
}

function prepareTaskCenterPlaceholders() {
    TASK_CENTER_INTERFACE_IDS.forEach((id) => {
        const select = document.getElementById(id);
        if (select && !select.options.length) {
            select.innerHTML = '<option value="">进入模块区域后加载网卡列表...</option>';
        }
    });

    const nicList = document.getElementById('taskNicList');
    if (nicList && !nicList.children.length) {
        nicList.innerHTML = '<div class="dashboard-empty">进入模块区域后加载网卡列表...</div>';
    }
}

async function ensureTaskCenterDataLoaded() {
    if (interfaceOptionsLoaded && nicOptionsLoaded) {
        return;
    }

    if (!taskCenterDataPromise) {
        taskCenterDataPromise = (async () => {
            await Promise.all([
                loadInterfaceOptions(),
                loadNICOptions()
            ]);
            restoreTaskPreferences();
        })().finally(() => {
            taskCenterDataPromise = null;
        });
    }

    await taskCenterDataPromise;
}

function scheduleTaskCenterLazyLoad() {
    const taskCenterGrid = document.querySelector('.task-center-grid');
    if (!taskCenterGrid) {
        return;
    }

    const section = taskCenterGrid.closest('section') || taskCenterGrid;
    const triggerLoad = () => {
        ensureTaskCenterDataLoaded();
    };

    taskCenterGrid.addEventListener('focusin', triggerLoad, { once: true });
    taskCenterGrid.addEventListener('pointerdown', triggerLoad, { once: true });

    if (typeof IntersectionObserver === 'function') {
        const observer = new IntersectionObserver((entries) => {
            if (entries.some((entry) => entry.isIntersecting)) {
                observer.disconnect();
                triggerLoad();
            }
        }, { rootMargin: '200px 0px' });

        observer.observe(section);
    }
}

function bindTaskCenterEvents() {
    document.getElementById('taskThreatStart').addEventListener('click', async () => {
        await ensureTaskCenterDataLoaded();
        controlTask('threat', buildThreatPayload());
    });
    document.getElementById('taskThreatStop').addEventListener('click', () => controlTask('threat', { action: 'stop' }));
    document.getElementById('taskBehaviorStart').addEventListener('click', async () => {
        await ensureTaskCenterDataLoaded();
        controlTask('behavior', buildBehaviorPayload());
    });
    document.getElementById('taskBehaviorStop').addEventListener('click', () => controlTask('behavior', { action: 'stop' }));
    document.getElementById('taskLanStart').addEventListener('click', async () => {
        await ensureTaskCenterDataLoaded();
        controlTask('lan', buildLANPayload());
    });
    document.getElementById('taskLanStop').addEventListener('click', () => controlTask('lan', { action: 'stop' }));
    document.getElementById('taskNicStart').addEventListener('click', async () => {
        await ensureTaskCenterDataLoaded();
        controlTask('nic', buildNICPayload());
    });
    document.getElementById('taskNicStop').addEventListener('click', () => controlTask('nic', { action: 'stop' }));

    [
        ['taskThreatInterface', STORAGE_KEYS.threat],
        ['taskThreatCount', STORAGE_KEYS.threat],
        ['taskThreatPort', STORAGE_KEYS.threat],
        ['taskBehaviorInterface', STORAGE_KEYS.behavior],
        ['taskBehaviorLimit', STORAGE_KEYS.behavior],
        ['taskLanInterface', STORAGE_KEYS.lan],
        ['taskLanThreatIntel', STORAGE_KEYS.lan]
    ].forEach(([id, key]) => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener('change', () => persistTaskPreferences(key));
        }
    });
}

async function loadOverview() {
    try {
        const response = await fetch('/api/product/overview');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        renderOverview(data);
    } catch (error) {
        renderFailure(error);
    }
}

async function loadTaskRuntimes() {
    await Promise.all(Object.keys(TASK_CONFIG).map(async (taskName) => {
        try {
            const response = await fetch(TASK_CONFIG[taskName].runtimeUrl);
            if (!response.ok) return;
            const runtime = await response.json();
            applyRuntimeState(taskName, runtime);
        } catch (error) {
            console.error(`load runtime failed for ${taskName}`, error);
        }
    }));
}

async function loadInterfaceOptions() {
    if (interfaceOptionsLoaded) {
        return true;
    }

    try {
        const response = await fetch('/api/interfaces');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const interfaces = await response.json();
        const options = interfaces.map((iface) => ({
            value: iface.rawName,
            label: iface.name
        }));

        TASK_CENTER_INTERFACE_IDS.forEach((id) => {
            const select = document.getElementById(id);
            if (!select) return;
            select.innerHTML = options.map((option) =>
                `<option value="${escapeHTML(option.value)}">${escapeHTML(option.label)}</option>`
            ).join('');
        });

        interfaceOptionsLoaded = true;
        return true;
    } catch (error) {
        console.error('load interfaces failed', error);
        return false;
    }
}

async function loadNICOptions() {
    if (nicOptionsLoaded) {
        return true;
    }

    try {
        const response = await fetch('/api/nic/list');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        const list = document.getElementById('taskNicList');
        if (!list) return false;

        if (!data.success || !Array.isArray(data.nics)) {
            list.innerHTML = '<div class="dashboard-empty">无法读取网卡列表。</div>';
            return;
        }

        list.innerHTML = data.nics.map((nic) => `
            <label class="task-checkbox-item">
                <input type="checkbox" value="${escapeHTML(nic.name)}">
                <span>${escapeHTML(nic.displayName || nic.name)}</span>
            </label>
        `).join('');

        list.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {
            checkbox.addEventListener('change', () => persistTaskPreferences(STORAGE_KEYS.nic));
        });
        nicOptionsLoaded = true;
        return true;
    } catch (error) {
        console.error('load nic list failed', error);
        return false;
    }
}

function restoreTaskPreferences() {
    const threat = readStorage(STORAGE_KEYS.threat, { interface: '', count: '20', port: '' });
    setValue('taskThreatInterface', threat.interface);
    setValue('taskThreatCount', threat.count || '20');
    setValue('taskThreatPort', threat.port || '');

    const behavior = readStorage(STORAGE_KEYS.behavior, { interface: '', limit: '30' });
    setValue('taskBehaviorInterface', behavior.interface);
    setValue('taskBehaviorLimit', behavior.limit || '30');

    const lan = readStorage(STORAGE_KEYS.lan, { interface: '', threatIntel: 'enabled' });
    setValue('taskLanInterface', lan.interface);
    setValue('taskLanThreatIntel', lan.threatIntel || 'enabled');

    const nic = readStorage(STORAGE_KEYS.nic, { nics: [] });
    if (Array.isArray(nic.nics)) {
        document.querySelectorAll('#taskNicList input[type="checkbox"]').forEach((checkbox) => {
            checkbox.checked = nic.nics.includes(checkbox.value);
        });
    }
}

function persistTaskPreferences(storageKey) {
    switch (storageKey) {
        case STORAGE_KEYS.threat:
            writeStorage(storageKey, {
                interface: getValue('taskThreatInterface'),
                count: getValue('taskThreatCount'),
                port: getValue('taskThreatPort')
            });
            break;
        case STORAGE_KEYS.behavior:
            writeStorage(storageKey, {
                interface: getValue('taskBehaviorInterface'),
                limit: getValue('taskBehaviorLimit')
            });
            break;
        case STORAGE_KEYS.lan:
            writeStorage(storageKey, {
                interface: getValue('taskLanInterface'),
                threatIntel: getValue('taskLanThreatIntel')
            });
            break;
        case STORAGE_KEYS.nic:
            writeStorage(storageKey, {
                nics: getSelectedTaskNics(),
                metric: readStorage(storageKey, {}).metric || 'total',
                timeWindow: readStorage(storageKey, {}).timeWindow || '600',
                mode: readStorage(storageKey, {}).mode || 'realtime'
            });
            break;
        default:
            break;
    }
}

function buildThreatPayload() {
    persistTaskPreferences(STORAGE_KEYS.threat);
    const aiSettings = readStorage(STORAGE_KEYS.ai, { provider: 'ollama', apiKey: '', apiBase: '', model: 'deepseek-r1:8b' });

    return {
        action: 'start',
        interface: getValue('taskThreatInterface'),
        count: getValue('taskThreatCount') || '20',
        port: getValue('taskThreatPort'),
        provider: aiSettings.provider || 'ollama',
        apiKey: aiSettings.apiKey || '',
        apiBase: aiSettings.apiBase || '',
        model: aiSettings.model || 'deepseek-r1:8b'
    };
}

function buildBehaviorPayload() {
    persistTaskPreferences(STORAGE_KEYS.behavior);
    const aiSettings = readStorage(STORAGE_KEYS.ai, { provider: 'ollama', apiKey: '', apiBase: '', model: 'deepseek-r1:8b' });

    return {
        action: 'start',
        interface: getValue('taskBehaviorInterface'),
        limit: getValue('taskBehaviorLimit') || '30',
        provider: aiSettings.provider || 'ollama',
        apiKey: aiSettings.apiKey || '',
        apiBase: aiSettings.apiBase || '',
        model: aiSettings.model || 'deepseek-r1:8b'
    };
}

function buildLANPayload() {
    persistTaskPreferences(STORAGE_KEYS.lan);
    return {
        action: 'start',
        interface: getValue('taskLanInterface'),
        no_threat_intel: getValue('taskLanThreatIntel') === 'disabled' ? 'true' : 'false'
    };
}

function buildNICPayload() {
    const preferences = readStorage(STORAGE_KEYS.nic, { metric: 'total', timeWindow: '600', mode: 'realtime' });
    const payload = {
        action: 'start',
        nics: getSelectedTaskNics()
    };
    writeStorage(STORAGE_KEYS.nic, {
        nics: payload.nics,
        metric: preferences.metric || 'total',
        timeWindow: preferences.timeWindow || '600',
        mode: preferences.mode || 'realtime'
    });
    return payload;
}

async function controlTask(taskName, payload) {
    try {
        const response = await fetch(TASK_CONFIG[taskName].controlUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || `HTTP ${response.status}`);
        }

        const runtime = await response.json();
        applyRuntimeState(taskName, runtime);
        await loadOverview();
    } catch (error) {
        const runtimeEl = document.getElementById(TASK_CONFIG[taskName].runtimeEl);
        if (runtimeEl) {
            runtimeEl.textContent = '执行失败';
            runtimeEl.classList.remove('active');
        }
        console.error(`control task failed for ${taskName}`, error);
    }
}

function applyRuntimeState(taskName, runtime) {
    const config = TASK_CONFIG[taskName];
    const runtimeEl = document.getElementById(config.runtimeEl);
    const startBtn = document.getElementById(config.startButton);
    const stopBtn = document.getElementById(config.stopButton);
    const isActive = Boolean(runtime.active);
    const runtimeStatus = runtime.runtimeStatus || (isActive ? 'running' : 'idle');
    const desiredState = runtime.desiredState || (isActive ? 'running' : 'stopped');
    const isRecovering = runtimeStatus === 'backoff';
    const isStopping = runtimeStatus === 'stopping';
    let runtimeLabel = '待机';

    if (isActive) {
        runtimeLabel = '运行中';
    } else if (isRecovering) {
        runtimeLabel = '自动恢复中';
    } else if (isStopping) {
        runtimeLabel = '正在停止';
    } else if (runtimeStatus === 'failed') {
        runtimeLabel = '启动失败';
    }

    if (runtimeEl) {
        runtimeEl.textContent = isActive ? '运行中' : '待机';
        runtimeEl.classList.toggle('active', isActive);
        runtimeEl.textContent = runtimeLabel;
        runtimeEl.title = runtime.lastExitReason || '';
    }
    if (startBtn) startBtn.disabled = isActive || isRecovering || isStopping || desiredState === 'running';
    if (stopBtn) stopBtn.disabled = !(isActive || isRecovering || isStopping || desiredState === 'running');

    const lastCommand = runtime.lastCommand || {};

    if (taskName === 'threat') {
        const preferences = {
            ...readStorage(STORAGE_KEYS.threat, { interface: '', count: '20', port: '' }),
            ...(lastCommand.interface ? { interface: lastCommand.interface } : {}),
            ...(lastCommand.count ? { count: lastCommand.count } : {}),
            ...(lastCommand.port !== undefined ? { port: lastCommand.port } : {})
        };
        writeStorage(STORAGE_KEYS.threat, preferences);
        setValue('taskThreatInterface', preferences.interface);
        setValue('taskThreatCount', preferences.count);
        setValue('taskThreatPort', preferences.port);
    } else if (taskName === 'behavior') {
        const preferences = {
            ...readStorage(STORAGE_KEYS.behavior, { interface: '', limit: '30' }),
            ...(lastCommand.interface ? { interface: lastCommand.interface } : {}),
            ...(lastCommand.limit ? { limit: lastCommand.limit } : {})
        };
        writeStorage(STORAGE_KEYS.behavior, preferences);
        setValue('taskBehaviorInterface', preferences.interface);
        setValue('taskBehaviorLimit', preferences.limit);
    } else if (taskName === 'lan') {
        const preferences = {
            ...readStorage(STORAGE_KEYS.lan, { interface: '', threatIntel: 'enabled' }),
            ...(lastCommand.interface ? { interface: lastCommand.interface } : {}),
            ...(lastCommand.no_threat_intel !== undefined
                ? { threatIntel: lastCommand.no_threat_intel === 'true' ? 'disabled' : 'enabled' }
                : {})
        };
        writeStorage(STORAGE_KEYS.lan, preferences);
        setValue('taskLanInterface', preferences.interface);
        setValue('taskLanThreatIntel', preferences.threatIntel);
    } else if (taskName === 'nic') {
        const preferences = {
            ...readStorage(STORAGE_KEYS.nic, { nics: [], metric: 'total', timeWindow: '600', mode: 'realtime' }),
            ...(Array.isArray(lastCommand.nics) ? { nics: lastCommand.nics } : {})
        };
        writeStorage(STORAGE_KEYS.nic, preferences);
        if (Array.isArray(lastCommand.nics)) {
            document.querySelectorAll('#taskNicList input[type="checkbox"]').forEach((checkbox) => {
                checkbox.checked = lastCommand.nics.includes(checkbox.value);
            });
        }
    }
}

function renderOverview(data) {
    const overview = data.overview || {};

    setText('coverageText', overview.monitoringCoverage || '暂无监控数据');
    setText('generatedAtText', `数据生成时间 ${formatDateTime(data.generatedAt)}`);
    setText('healthyModulesValue', overview.healthyModules || 0);
    setText('activeNicsValue', overview.activeNICs || 0);
    setText('highRiskAssetsValue', overview.highRiskAssets || 0);
    setText('threatEventsValue', overview.threatEvents || 0);

    setText('totalPacketsValue', formatNumber(overview.totalPackets));
    setText('threatRateValue', `${formatPercentage(overview.threatRate)}%`);
    setText('behaviorSessionsValue', formatNumber(overview.behaviorSessions));
    setText('lanAssetsValue', formatNumber(overview.lanAssets));

    renderModules(data.modules || []);
    renderThreatTypes(data.threatTypes || []);
    renderDailyTrends(data.dailyTrends || []);
    renderRecentEvents(data.recentEvents || []);
    renderAssets(data.topAssets || []);
    renderNICRanking(data.nicRanking || []);
}

function renderModules(modules) {
    const container = document.getElementById('modulesGrid');
    if (!container) return;

    if (!modules.length) {
        container.innerHTML = emptyState('暂无模块运行数据。');
        return;
    }

    container.innerHTML = modules.map((module) => `
        <article class="module-card">
            <div class="module-header">
                <div class="module-title">${escapeHTML(module.name)}</div>
                <span class="module-status status-${escapeHTML(module.status)}">${escapeHTML(module.statusLabel)}</span>
            </div>
            <div class="module-metric">${escapeHTML(module.metric)}</div>
            <div class="module-detail">${escapeHTML(module.detail)}</div>
            <div class="module-updated">${module.updatedAt ? `最近更新 ${escapeHTML(module.updatedAt)}` : '暂无历史更新'}</div>
            <a class="module-link" href="${escapeHTML(module.url)}">进入模块</a>
        </article>
    `).join('');
}

function renderThreatTypes(items) {
    const container = document.getElementById('threatTypeList');
    if (!container) return;

    if (!items.length) {
        container.innerHTML = emptyState('还没有威胁类型样本，说明当前库中没有威胁检出。');
        return;
    }

    const maxValue = Math.max(...items.map((item) => item.value || 0), 1);
    container.innerHTML = items.map((item) => `
        <div class="distribution-item">
            <div>
                <strong>${escapeHTML(item.label)}</strong>
                <div class="distribution-bar"><span style="width:${Math.max(8, ((item.value || 0) / maxValue) * 100)}%"></span></div>
            </div>
            <strong>${formatNumber(item.value)}</strong>
        </div>
    `).join('');
}

function renderDailyTrends(items) {
    const container = document.getElementById('trendChart');
    if (!container) return;

    if (!items.length) {
        container.innerHTML = emptyState('暂无趋势数据。');
        return;
    }

    const maxValue = Math.max(
        ...items.map((item) => Math.max(item.packets || 0, item.threats || 0, item.behaviors || 0, item.lanReports || 0)),
        1
    );

    container.innerHTML = items.map((item) => `
        <div class="trend-day">
            <div class="trend-bars">
                <div class="trend-bar packets" style="height:${scaleHeight(item.packets, maxValue)}%"></div>
                <div class="trend-bar threats" style="height:${scaleHeight(item.threats, maxValue)}%"></div>
                <div class="trend-bar behaviors" style="height:${scaleHeight(item.behaviors, maxValue)}%"></div>
                <div class="trend-bar lan" style="height:${scaleHeight(item.lanReports, maxValue)}%"></div>
            </div>
            <div class="trend-meta">${formatNumber(item.threats)} 个威胁</div>
            <div class="trend-label">${formatShortDate(item.date)}</div>
        </div>
    `).join('');
}

function renderRecentEvents(items) {
    const container = document.getElementById('eventFeed');
    if (!container) return;

    const visibleItems = items.slice(0, 5);
    if (!visibleItems.length) {
        container.innerHTML = emptyState('最近没有异常事件。');
        return;
    }

    container.innerHTML = visibleItems.map((item) => `
        <article class="event-item ${escapeHTML(item.severity || 'info')}">
            <div class="event-topline">
                <span>${escapeHTML(sourceLabel(item.source))}</span>
                <span>${escapeHTML(item.at || formatDateTime(item.timestamp * 1000))}</span>
            </div>
            <div class="event-title">${escapeHTML(item.title)}</div>
            <div class="event-detail">${escapeHTML(item.detail)}</div>
        </article>
    `).join('');
}

function renderAssets(items) {
    const container = document.getElementById('assetTable');
    if (!container) return;

    if (!items.length) {
        container.innerHTML = emptyState('资产画像尚未形成。');
        return;
    }

    container.innerHTML = `
        <div class="asset-head">
            <span>资产</span>
            <span>风险等级</span>
            <span>威胁事件</span>
            <span>请求数</span>
            <span>最近观测</span>
        </div>
        ${items.map((item) => `
            <div class="asset-row">
                <strong>${escapeHTML(item.ip)}</strong>
                <span class="risk-pill ${escapeHTML(item.riskLevel)}">${riskLabel(item.riskLevel)} / ${formatNumber(item.riskScore)}</span>
                <span>${formatNumber(item.threatEvents)}</span>
                <span>${formatNumber(item.requests)} / ${formatNumber(item.uniqueDomains)} 域名</span>
                <span>${escapeHTML(item.lastSeen || '--')}</span>
            </div>
        `).join('')}
    `;
}

function renderNICRanking(items) {
    const container = document.getElementById('nicRanking');
    if (!container) return;

    if (!items.length) {
        container.innerHTML = emptyState('尚未采集到网卡实时数据。');
        return;
    }

    const maxValue = Math.max(...items.map((item) => item.totalBps || 0), 1);
    container.innerHTML = items.map((item) => `
        <div class="nic-item">
            <div class="nic-topline">
                <span class="nic-name">${escapeHTML(item.name)}</span>
                <span class="nic-mbps">${formatMbps(item.totalMbps)}</span>
            </div>
            <div class="nic-bar"><span style="width:${Math.max(8, ((item.totalBps || 0) / maxValue) * 100)}%"></span></div>
            <div class="nic-detail">RX ${formatBps(item.rxBps)} / TX ${formatBps(item.txBps)}</div>
        </div>
    `).join('');
}

function renderFailure(error) {
    setText('coverageText', '无法加载产品数据');
    setText('generatedAtText', error.message || '未知错误');

    const message = emptyState('产品总览接口读取失败，请确认 Go 服务已经启动并且 SQLite 数据可访问。');
    ['modulesGrid', 'threatTypeList', 'trendChart', 'eventFeed', 'assetTable', 'nicRanking'].forEach((id) => {
        const element = document.getElementById(id);
        if (element) {
            element.innerHTML = message;
        }
    });
}

function getSelectedTaskNics() {
    return Array.from(document.querySelectorAll('#taskNicList input[type="checkbox"]:checked')).map((checkbox) => checkbox.value);
}

function readStorage(key, fallback = {}) {
    try {
        const raw = localStorage.getItem(key);
        if (!raw) return fallback;
        return { ...fallback, ...JSON.parse(raw) };
    } catch (error) {
        return fallback;
    }
}

function writeStorage(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
}

function getValue(id) {
    const element = document.getElementById(id);
    return element ? element.value : '';
}

function setValue(id, value) {
    const element = document.getElementById(id);
    if (element && value !== undefined && value !== null) {
        element.value = value;
    }
}

function formatNumber(value) {
    return Number(value || 0).toLocaleString('zh-CN');
}

function formatPercentage(value) {
    return Number(value || 0).toFixed(1);
}

function formatDateTime(value) {
    if (!value) return '--';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '--';
    return date.toLocaleString('zh-CN', { hour12: false });
}

function formatShortDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value || '--';
    }
    return `${date.getMonth() + 1}/${date.getDate()}`;
}

function formatBps(value) {
    const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    let current = Number(value || 0);
    let index = 0;
    while (current >= 1000 && index < units.length - 1) {
        current /= 1000;
        index += 1;
    }
    return `${current.toFixed(1)} ${units[index]}`;
}

function formatMbps(value) {
    return `${Number(value || 0).toFixed(2)} Mbps`;
}

function scaleHeight(value, maxValue) {
    return Math.max(8, (Number(value || 0) / maxValue) * 100);
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function emptyState(message) {
    return `<div class="dashboard-empty">${escapeHTML(message)}</div>`;
}

function escapeHTML(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function sourceLabel(source) {
    const mapping = {
        threat_detection: '威胁检测',
        threat: '威胁检测',
        behavior_analysis: '行为分析',
        behavior: '行为分析',
        lan_monitor: '局域网监控',
        'lan-monitor': '局域网监控',
        nic_monitor: '网卡流量',
        'nic-monitor': '网卡流量',
        website_security: '网站安全'
    };
    return mapping[source] || source || '系统';
}

function riskLabel(level) {
    const mapping = {
        high: '高风险',
        medium: '中风险',
        low: '低风险'
    };
    return mapping[level] || '未知';
}
