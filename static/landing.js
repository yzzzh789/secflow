document.addEventListener('DOMContentLoaded', () => {
    setupReveal();
    loadOverview();
    window.setInterval(loadOverview, 15000);
});

async function loadOverview() {
    try {
        const response = await fetch('/api/product/overview', { cache: 'no-store' });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        renderOverview(data);
    } catch (error) {
        renderFallback(error);
    }
}

function renderOverview(data) {
    const overview = data.overview || {};
    const modules = Array.isArray(data.modules) ? data.modules : [];

    setText('metricCoverage', overview.monitoringCoverage || '暂无数据');
    setText('metricPackets', formatNumber(overview.totalPackets || 0));
    setText('metricThreats', formatNumber(overview.threatEvents || 0));
    setText('metricNics', formatNumber(overview.activeNICs || 0));
    setText('metricAssets', formatNumber(overview.highRiskAssets || 0));
    setText('metricBehaviors', formatNumber(overview.behaviorSessions || 0));
    setText('metricHealthyModules', formatNumber(overview.healthyModules || 0));
    setText('metricThreatRate', `${formatPercentage(overview.threatRate || 0)}%`);

    const generatedAt = formatDateTime(data.generatedAt);
    setText('generatedAtLabel', generatedAt);
    setText('metricGeneratedAt', generatedAt);
    setText('liveCoverageHeadline', overview.monitoringCoverage || '当前暂无监测覆盖');
    setText('liveCoverageMeta', buildCoverageMeta(overview, modules.length));

    renderEvents(data.recentEvents || []);
    renderModules(modules);
    renderThreatTypes(data.threatTypes || []);
    renderTopAssets(data.topAssets || []);
    renderDailyTrends(data.dailyTrends || []);
}

function renderEvents(events) {
    const container = document.getElementById('landingEvents');
    if (!container) return;

    if (!events.length) {
        container.innerHTML = '<div class="empty-inline">当前没有最新事件样本。</div>';
        return;
    }

    container.innerHTML = events.slice(0, 3).map((event) => `
        <article class="event-item-mini">
            <strong>${escapeHTML(event.title || '事件')}</strong>
            <span>${escapeHTML(sourceLabel(event.source))} · ${escapeHTML(event.at || formatDateTime((event.timestamp || 0) * 1000))}</span>
            <p>${escapeHTML(event.detail || '暂无详细信息')}</p>
        </article>
    `).join('');
}

function renderModules(modules) {
    const compactContainer = document.getElementById('landingModules');
    const boardContainer = document.getElementById('liveModuleBoard');
    if (!compactContainer || !boardContainer) return;

    if (!modules.length) {
        compactContainer.innerHTML = '<div class="empty-inline">当前没有模块运行数据。</div>';
        boardContainer.innerHTML = '<div class="empty-board">模块状态将在这里显示。</div>';
        return;
    }

    compactContainer.innerHTML = modules.map((module) => `
        <article class="module-chip">
            <div>
                <strong>${escapeHTML(module.name || '模块')}</strong>
                <span>${escapeHTML(module.metric || '暂无指标')}</span>
            </div>
            <span class="status-pill ${statusClass(module.status)}">${escapeHTML(module.statusLabel || '未知')}</span>
        </article>
    `).join('');

    boardContainer.innerHTML = modules.map((module) => `
        <article class="live-module-card">
            <div class="module-chip">
                <div>
                    <strong>${escapeHTML(module.name || '模块')}</strong>
                    <span>${escapeHTML(module.updatedAt ? `最近更新 ${module.updatedAt}` : '暂无更新时间')}</span>
                </div>
                <span class="status-pill ${statusClass(module.status)}">${escapeHTML(module.statusLabel || '未知')}</span>
            </div>
            <p>${escapeHTML(module.metric || '暂无指标')}</p>
            <span>${escapeHTML(module.detail || '暂无模块描述')}</span>
        </article>
    `).join('');
}

function renderThreatTypes(items) {
    const container = document.getElementById('threatMixList');
    if (!container) return;

    if (!items.length) {
        container.innerHTML = '<div class="empty-inline">当前没有威胁类型统计。</div>';
        return;
    }

    const maxValue = Math.max(...items.map((item) => Number(item.value) || 0), 1);
    container.innerHTML = items.slice(0, 5).map((item) => {
        const value = Number(item.value) || 0;
        const width = Math.max(8, Math.round(value / maxValue * 100));
        return `
            <article class="threat-row">
                <div class="threat-row-top">
                    <strong>${escapeHTML(item.label || '未分类')}</strong>
                    <em>${formatNumber(value)}</em>
                </div>
                <div class="threat-bar">
                    <div class="threat-bar-fill" style="width:${width}%"></div>
                </div>
                <span>${escapeHTML(buildThreatHint(item.label, value))}</span>
            </article>
        `;
    }).join('');
}

function renderTopAssets(items) {
    const container = document.getElementById('topAssetList');
    if (!container) return;

    if (!items.length) {
        container.innerHTML = '<div class="empty-inline">当前没有高风险资产线索。</div>';
        return;
    }

    container.innerHTML = items.slice(0, 4).map((item) => `
        <article class="asset-item">
            <div class="asset-row">
                <strong>${escapeHTML(item.ip || '未知 IP')}</strong>
                <span class="asset-badge ${riskBadgeClass(item.riskLevel)}">${escapeHTML(riskLabel(item.riskLevel))}</span>
            </div>
            <span>风险分 ${formatNumber(item.riskScore || 0)} · 威胁事件 ${formatNumber(item.threatEvents || 0)} · 请求 ${formatNumber(item.requests || 0)}</span>
            <div class="asset-meta">
                <span class="asset-badge">域名 ${formatNumber(item.uniqueDomains || 0)}</span>
                <span class="asset-badge">最近 ${escapeHTML(item.lastSeen || '--')}</span>
            </div>
        </article>
    `).join('');
}

function renderDailyTrends(items) {
    const container = document.getElementById('trendStrip');
    if (!container) return;

    if (!items.length) {
        container.innerHTML = '<div class="empty-inline">当前没有趋势数据。</div>';
        return;
    }

    const recent = items.slice(-7);
    const maxValue = Math.max(...recent.map((item) => {
        const packets = Number(item.packets) || 0;
        const threats = Number(item.threats) || 0;
        const behaviors = Number(item.behaviors) || 0;
        const lanReports = Number(item.lanReports) || 0;
        return Math.max(packets, threats, behaviors, lanReports);
    }), 1);

    container.innerHTML = recent.map((item) => {
        const packets = scaleTrendValue(item.packets, maxValue);
        const threats = scaleTrendValue(item.threats, maxValue);
        const behaviors = scaleTrendValue(item.behaviors, maxValue);
        const lanReports = scaleTrendValue(item.lanReports, maxValue);

        return `
            <article class="trend-bar-card">
                <div class="trend-bar-stack">
                    <div class="trend-bar trend-bar-packets" style="height:${packets}px" title="报文 ${formatNumber(item.packets || 0)}"></div>
                    <div class="trend-bar trend-bar-threats" style="height:${threats}px" title="威胁 ${formatNumber(item.threats || 0)}"></div>
                    <div class="trend-bar trend-bar-behaviors" style="height:${behaviors}px" title="行为 ${formatNumber(item.behaviors || 0)}"></div>
                    <div class="trend-bar trend-bar-lan" style="height:${lanReports}px" title="资产 ${formatNumber(item.lanReports || 0)}"></div>
                </div>
                <strong>${escapeHTML(formatDayLabel(item.date))}</strong>
                <span class="trend-label">报文 ${formatNumber(item.packets || 0)} / 威胁 ${formatNumber(item.threats || 0)}</span>
            </article>
        `;
    }).join('');
}

function renderFallback(error) {
    setText('metricCoverage', '接口离线');
    setText('generatedAtLabel', '未连接');
    setText('metricGeneratedAt', '--');
    setText('liveCoverageHeadline', '无法读取实时概览');
    setText('liveCoverageMeta', '请确认 Go 服务已启动，并且数据文件可访问。');

    const message = escapeHTML(error.message || '未知错误');
    const fallbackMessage = `<div class="empty-inline">概览接口读取失败：${message}</div>`;
    const fallbackBoard = '<div class="empty-board">接口恢复后会自动展示模块状态。</div>';

    setHTML('landingEvents', fallbackMessage);
    setHTML('landingModules', fallbackMessage);
    setHTML('threatMixList', fallbackMessage);
    setHTML('topAssetList', fallbackMessage);
    setHTML('trendStrip', fallbackMessage);
    setHTML('liveModuleBoard', fallbackBoard);
}

function buildCoverageMeta(overview, moduleCount) {
    const threatEvents = formatNumber(overview.threatEvents || 0);
    const activeNICs = formatNumber(overview.activeNICs || 0);
    const highRiskAssets = formatNumber(overview.highRiskAssets || 0);
    const healthyModules = formatNumber(overview.healthyModules || 0);
    return `当前共有 ${moduleCount} 个模块视图，其中 ${healthyModules} 个处于健康状态；累计发现 ${threatEvents} 个威胁事件、${highRiskAssets} 个高风险资产，监测到 ${activeNICs} 张活跃网卡。`;
}

function buildThreatHint(label, value) {
    if (!label) return `累计 ${formatNumber(value)} 条线索`;

    const mapping = {
        'SQL Injection': '数据库攻击类线索需要优先排查源请求与目标路径',
        'XSS': '前端输入点相关风险，适合结合网站监测联动排查',
        'Port Scan': '可能对应踩点或横向侦察行为',
        'DDoS': '需结合带宽与网卡流量页面确认突发占用',
    };

    return mapping[label] || `累计 ${formatNumber(value)} 条该类型威胁线索`;
}

function sourceLabel(source) {
    const mapping = {
        threat_detection: '威胁检测',
        behavior_analysis: '行为分析',
        lan_monitor: '局域网监控',
        nic_monitor: '网卡流量',
        website_security: '网站安全'
    };

    return mapping[source] || '系统事件';
}

function statusClass(status) {
    const normalized = String(status || '').toLowerCase();
    const mapping = {
        healthy: 'status-healthy',
        running: 'status-running',
        warning: 'status-warning',
        stale: 'status-stale',
        idle: 'status-idle',
        stopped: 'status-stopped',
        backoff: 'status-backoff',
        failed: 'status-failed',
        error: 'status-error'
    };

    return mapping[normalized] || 'status-unknown';
}

function riskLabel(level) {
    const mapping = {
        high: '高风险',
        medium: '中风险',
        low: '低风险'
    };

    return mapping[String(level || '').toLowerCase()] || '待判断';
}

function riskBadgeClass(level) {
    const normalized = String(level || '').toLowerCase();
    if (normalized === 'high') return 'asset-badge-high';
    if (normalized === 'medium') return 'asset-badge-medium';
    if (normalized === 'low') return 'asset-badge-low';
    return '';
}

function scaleTrendValue(value, maxValue) {
    const numeric = Number(value) || 0;
    if (!numeric) return 8;
    return Math.max(12, Math.round(numeric / maxValue * 118));
}

function formatDayLabel(value) {
    if (!value) return '--';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return String(value).slice(5);
    }

    return new Intl.DateTimeFormat('zh-CN', {
        month: '2-digit',
        day: '2-digit'
    }).format(date);
}

function setupReveal() {
    const elements = document.querySelectorAll('.reveal');
    if (!elements.length) return;

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add('is-visible');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.14 });

    elements.forEach((element) => observer.observe(element));
}

function formatNumber(value) {
    return new Intl.NumberFormat('zh-CN').format(Number(value) || 0);
}

function formatPercentage(value) {
    const number = Number(value) || 0;
    return number.toFixed(number >= 10 ? 1 : 2).replace(/\.00$/, '');
}

function formatDateTime(value) {
    if (!value) return '--';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '--';

    return new Intl.DateTimeFormat('zh-CN', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    }).format(date);
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function setHTML(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.innerHTML = value;
    }
}

function escapeHTML(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
