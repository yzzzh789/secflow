const websiteSecurityState = {
    pollTimer: null,
    data: {
        websites: [],
        threats: [],
        logs: [],
        metrics: {
            totalWebsites: 0,
            healthyWebsites: 0,
            activeIssues: 0,
            highRiskIssues: 0
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
    refreshState();
    websiteSecurityState.pollTimer = window.setInterval(refreshState, 15000);
});

function bindEvents() {
    document.getElementById('addWebsiteBtn').addEventListener('click', addWebsite);
    document.getElementById('checkNowBtn').addEventListener('click', () => runCheck());
    document.getElementById('clearThreatsBtn').addEventListener('click', clearThreats);
    document.getElementById('siteList').addEventListener('click', handleSiteListAction);
}

async function apiRequest(path, options = {}) {
    const response = await fetch(path, {
        headers: {
            'Content-Type': 'application/json',
            ...(options.headers || {})
        },
        ...options
    });

    if (!response.ok) {
        const errorText = (await response.text()).trim();
        throw new Error(errorText || '请求失败');
    }

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        return response.json();
    }
    return null;
}

async function refreshState() {
    try {
        const data = await apiRequest('/api/website-security/state');
        websiteSecurityState.data = data;
        setBackendStatus(true);
        renderAll();
    } catch (error) {
        setBackendStatus(false, error.message);
        console.error(error);
    }
}

function renderAll() {
    renderMetrics();
    renderModuleCards();
    renderSiteList();
    renderThreatList();
    renderLogViewer();
}

function renderMetrics() {
    const metrics = websiteSecurityState.data.metrics || {};
    document.getElementById('totalWebsites').textContent = metrics.totalWebsites || 0;
    document.getElementById('healthyWebsites').textContent = metrics.healthyWebsites || 0;
    document.getElementById('activeIssues').textContent = metrics.activeIssues || 0;
    document.getElementById('highRiskIssues').textContent = metrics.highRiskIssues || 0;
}

function renderModuleCards() {
    const websites = websiteSecurityState.data.websites || [];

    renderIssueModuleCard('tamper', websites, {
        issueCountLabel: 'tamperIssueCount',
        lastCheckLabel: 'tamperLastCheck',
        messageLabel: 'tamperMessage',
        statusLabel: 'tamperStatus'
    });
    renderIssueModuleCard('malware', websites, {
        issueCountLabel: 'malwareIssueCount',
        lastCheckLabel: 'malwareLastCheck',
        messageLabel: 'malwareMessage',
        statusLabel: 'malwareStatus'
    });
    renderIssueModuleCard('content', websites, {
        issueCountLabel: 'contentIssueCount',
        lastCheckLabel: 'contentLastCheck',
        messageLabel: 'contentMessage',
        statusLabel: 'contentStatus'
    });
    renderIssueModuleCard('baseline', websites, {
        issueCountLabel: 'baselineIssueCount',
        lastCheckLabel: 'baselineLastCheck',
        messageLabel: 'baselineMessage',
        statusLabel: 'baselineStatus'
    });
    renderIssueModuleCard('exposure', websites, {
        issueCountLabel: 'exposureIssueCount',
        lastCheckLabel: 'exposureLastCheck',
        messageLabel: 'exposureMessage',
        statusLabel: 'exposureStatus'
    });

    renderAvailabilityCard(websites);
}

function renderIssueModuleCard(key, websites, ids) {
    if (websites.length === 0) {
        updateStatusChip(ids.statusLabel, 'pending');
        document.getElementById(ids.messageLabel).textContent = '暂无监测数据';
        document.getElementById(ids.issueCountLabel).textContent = '0';
        document.getElementById(ids.lastCheckLabel).textContent = '--';
        return;
    }

    const checks = websites.map(site => site.checks[key]);
    const overallStatus = pickOverallStatus(checks.map(check => check.status));
    const topCheck = pickPriorityCheck(checks);
    const issueCount = checks.reduce((sum, check) => sum + (check.issueCount || 0), 0);
    const lastCheck = latestTime(checks.map(check => check.lastCheckAt));

    updateStatusChip(ids.statusLabel, overallStatus);
    document.getElementById(ids.messageLabel).textContent = topCheck.message || '暂无监测数据';
    document.getElementById(ids.issueCountLabel).textContent = String(issueCount);
    document.getElementById(ids.lastCheckLabel).textContent = formatDateTime(lastCheck);
}

function renderAvailabilityCard(websites) {
    if (websites.length === 0) {
        updateStatusChip('availabilityStatus', 'pending');
        document.getElementById('availabilityMessage').textContent = '暂无监测数据';
        document.getElementById('avgResponseTime').textContent = '--';
        document.getElementById('avgUptime').textContent = '--';
        return;
    }

    const checks = websites.map(site => site.checks.availability);
    const overallStatus = pickOverallStatus(checks.map(check => check.status));
    const topCheck = pickPriorityCheck(checks);
    const responseTimes = checks.map(check => check.responseTimeMs).filter(value => value > 0);
    const uptimes = checks.map(check => check.uptime).filter(value => typeof value === 'number');

    updateStatusChip('availabilityStatus', overallStatus);
    document.getElementById('availabilityMessage').textContent = topCheck.message || '暂无监测数据';
    document.getElementById('avgResponseTime').textContent = responseTimes.length ? `${Math.round(average(responseTimes))} ms` : '--';
    document.getElementById('avgUptime').textContent = uptimes.length ? `${average(uptimes).toFixed(2)}%` : '--';
}

function renderSiteList() {
    const siteList = document.getElementById('siteList');
    const websites = websiteSecurityState.data.websites || [];

    if (websites.length === 0) {
        siteList.innerHTML = '<div class="site-card"><div class="empty-state">暂无监测网站，先添加一个网址开始。</div></div>';
        return;
    }

    siteList.innerHTML = websites.map(site => `
        <article class="site-card">
            <div class="site-header">
                <div>
                    <a class="site-url" href="${escapeHTML(site.url)}" target="_blank" rel="noreferrer">${escapeHTML(site.url)}</a>
                    <div class="site-meta">间隔 ${site.intervalMinutes} 分钟</div>
                </div>
                <span class="status-chip ${statusClassName(site.summaryStatus)}">${statusText(site.summaryStatus)}</span>
            </div>
            <div class="site-meta">
                摘要: ${escapeHTML(site.summaryMessage || '暂无')}<br>
                最近检测: ${formatDateTime(site.lastCheckAt)}<br>
                下次检测: ${formatDateTime(site.nextCheckAt)}<br>
                HTTP 状态: ${site.checks.availability.httpStatus || '--'}<br>
                响应时间: ${site.checks.availability.responseTimeMs ? `${site.checks.availability.responseTimeMs} ms` : '--'}<br>
                ${site.lastError ? `最近错误: ${escapeHTML(site.lastError)}` : '最近错误: 无'}
            </div>
            <div class="site-actions">
                <button class="btn btn-outline" data-action="check" data-id="${site.id}">${site.checking ? '检测中...' : '立即检测'}</button>
                <button class="btn btn-outline" data-action="remove" data-id="${site.id}">移除</button>
            </div>
        </article>
    `).join('');
}

function renderThreatList() {
    const threatList = document.getElementById('threatList');
    const threats = websiteSecurityState.data.threats || [];

    if (threats.length === 0) {
        threatList.innerHTML = '<p class="empty-state">暂无威胁事件。</p>';
        return;
    }

    threatList.innerHTML = threats.map(threat => `
        <div class="threat-item ${threat.severity === 'medium' ? 'warning' : ''}">
            <strong>${escapeHTML(threat.title)}</strong>
            <p>网站: ${escapeHTML(threat.websiteUrl)}</p>
            <p>说明: ${escapeHTML(threat.description)}</p>
            <p>级别: ${escapeHTML(threat.severity.toUpperCase())}</p>
            <p>时间: ${formatDateTime(threat.time)}</p>
        </div>
    `).join('');
}

function renderLogViewer() {
    const logViewer = document.getElementById('logViewer');
    const logs = websiteSecurityState.data.logs || [];

    if (logs.length === 0) {
        logViewer.innerHTML = '<div class="log-entry"><span class="log-time">--</span><span>暂无日志。</span></div>';
        return;
    }

    logViewer.innerHTML = logs.map(log => `
        <div class="log-entry">
            <span class="log-time">${formatDateTime(log.time)}</span>
            <span>[${escapeHTML(log.type)}]</span>
            <span>${escapeHTML(log.message)}</span>
        </div>
    `).join('');
}

async function addWebsite() {
    const urlInput = document.getElementById('websiteUrl');
    const intervalInput = document.getElementById('checkInterval');
    const url = urlInput.value.trim();
    const intervalMinutes = Number(intervalInput.value);

    if (!url) {
        alert('请输入网站地址');
        return;
    }

    try {
        await apiRequest('/api/website-security/websites', {
            method: 'POST',
            body: JSON.stringify({ url, intervalMinutes })
        });
        urlInput.value = '';
        await refreshState();
    } catch (error) {
        alert(error.message);
    }
}

async function runCheck(id = '') {
    try {
        const query = id ? `?id=${encodeURIComponent(id)}` : '';
        await apiRequest(`/api/website-security/check${query}`, { method: 'POST' });
        window.setTimeout(refreshState, 800);
    } catch (error) {
        alert(error.message);
    }
}

async function clearThreats() {
    if (!window.confirm('确定要清空网站安全事件吗？')) {
        return;
    }

    try {
        await apiRequest('/api/website-security/threats/clear', { method: 'POST' });
        await refreshState();
    } catch (error) {
        alert(error.message);
    }
}

async function handleSiteListAction(event) {
    const button = event.target.closest('button[data-action]');
    if (!button) {
        return;
    }

    const id = button.dataset.id;
    const action = button.dataset.action;
    if (!id || !action) {
        return;
    }

    if (action === 'check') {
        await runCheck(id);
        return;
    }

    if (action === 'remove') {
        if (!window.confirm('确定要移除这个网站监测项吗？')) {
            return;
        }
        try {
            await apiRequest(`/api/website-security/websites?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
            await refreshState();
        } catch (error) {
            alert(error.message);
        }
    }
}

function setBackendStatus(isConnected, message = '') {
    const badge = document.getElementById('backendStatus');
    badge.className = `hero-badge ${isConnected ? '' : 'status-danger'}`.trim();
    badge.textContent = isConnected ? '后端监测已连接' : `后端连接异常${message ? `: ${message}` : ''}`;
}

function updateStatusChip(id, status) {
    const element = document.getElementById(id);
    element.className = `status-chip ${statusClassName(status)}`;
    element.textContent = statusText(status);
}

function pickOverallStatus(statuses) {
    if (statuses.includes('danger')) return 'danger';
    if (statuses.includes('warning')) return 'warning';
    if (statuses.includes('pending')) return 'pending';
    return 'safe';
}

function pickPriorityCheck(checks) {
    return checks.find(check => check.status === 'danger')
        || checks.find(check => check.status === 'warning')
        || checks.find(check => check.status === 'pending')
        || checks[0]
        || { message: '暂无监测数据' };
}

function latestTime(values) {
    const timestamps = values.filter(Boolean).map(value => new Date(value).getTime()).filter(Number.isFinite);
    if (!timestamps.length) {
        return '';
    }
    return new Date(Math.max(...timestamps)).toISOString();
}

function average(values) {
    return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function formatDateTime(value) {
    if (!value) {
        return '--';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return '--';
    }
    return date.toLocaleString('zh-CN', { hour12: false });
}

function statusText(status) {
    switch (status) {
        case 'safe': return '正常';
        case 'warning': return '告警';
        case 'danger': return '高危';
        case 'pending': return '待检测';
        default: return '未知';
    }
}

function statusClassName(status) {
    switch (status) {
        case 'safe': return 'status-safe';
        case 'warning': return 'status-warning';
        case 'danger': return 'status-danger';
        default: return 'status-pending';
    }
}

function escapeHTML(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}
