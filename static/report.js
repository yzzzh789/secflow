document.addEventListener('DOMContentLoaded', () => {
    const STORAGE_KEY = 'behavior_analysis_preferences_v2';
    const MAX_LIVE_SESSIONS = 120;
    const runtimeClient = window.SecflowTaskRuntime || {};
    const createManagedTaskPage = runtimeClient.createManagedTaskPage;
    const escapeHTML = runtimeClient.escapeHTML || fallbackEscapeHTML;
    const loadJSONStorage = runtimeClient.loadJSONStorage || fallbackLoadJSONStorage;
    const saveJSONStorage = runtimeClient.saveJSONStorage || fallbackSaveJSONStorage;
    const state = {
        socket: null,
        isRunning: false,
        reconnectRequested: false,
        pendingStartPayload: null,
        liveSessions: new Map(),
        latestReport: null,
        webLogs: { page: 1, pageSize: 10, total: 0 },
        searchLogs: { page: 1, pageSize: 10, total: 0 }
    };

    const elements = {
        interfaceSelect: document.getElementById('interface-select'),
        timeLimitInput: document.getElementById('time-limit'),
        startBtn: document.getElementById('start-btn'),
        stopBtn: document.getElementById('stop-btn'),
        refreshAllBtn: document.getElementById('refresh-all-btn'),
        liveStatus: document.getElementById('live-status'),
        liveSessions: document.getElementById('live-sessions'),
        reportTypeSelect: document.getElementById('report-type-select'),
        generateWeeklyBtn: document.getElementById('generate-weekly-btn'),
        generateMonthlyBtn: document.getElementById('generate-monthly-btn'),
        downloadLatestBtn: document.getElementById('download-latest-btn'),
        latestReportMeta: document.getElementById('latest-report-meta'),
        webStart: document.getElementById('web-start'),
        webEnd: document.getElementById('web-end'),
        webSrcIP: document.getElementById('web-src-ip'),
        webDomain: document.getElementById('web-domain'),
        webCategory: document.getElementById('web-category'),
        webQueryBtn: document.getElementById('web-query-btn'),
        webLogBody: document.getElementById('web-log-body'),
        webPrevBtn: document.getElementById('web-prev-btn'),
        webNextBtn: document.getElementById('web-next-btn'),
        webPageInfo: document.getElementById('web-page-info'),
        searchStart: document.getElementById('search-start'),
        searchEnd: document.getElementById('search-end'),
        searchSrcIP: document.getElementById('search-src-ip'),
        searchEngine: document.getElementById('search-engine'),
        searchKeyword: document.getElementById('search-keyword'),
        searchQueryBtn: document.getElementById('search-query-btn'),
        searchLogBody: document.getElementById('search-log-body'),
        searchPrevBtn: document.getElementById('search-prev-btn'),
        searchNextBtn: document.getElementById('search-next-btn'),
        searchPageInfo: document.getElementById('search-page-info'),
        topSites: document.getElementById('top-sites'),
        topApps: document.getElementById('top-apps'),
        violationTotal: document.getElementById('violation-total'),
        violationTypes: document.getElementById('violation-types'),
        violationSeverity: document.getElementById('violation-severity'),
        violationBody: document.getElementById('violation-body')
    };

    if (createManagedTaskPage) {
        state.managedPage = createManagedTaskPage({
            runtimePath: '/api/runtime/behavior',
            wsPath: '/ws/report',
            reconnectMs: 1200,
            onSocketOpen: (_event, activeSocket) => {
                state.socket = activeSocket;
                updateRunState(true, 'Connected');
            },
            onMessage: handleLiveMessage,
            onError: handleReportSocketError,
            onSocketClose: handleReportSocketClose
        });
    }

    elements.startBtn.addEventListener('click', startAnalysis);
    elements.stopBtn.addEventListener('click', stopAnalysis);
    elements.refreshAllBtn.addEventListener('click', refreshAllAuditViews);
    elements.generateWeeklyBtn.addEventListener('click', () => generateReport('weekly'));
    elements.generateMonthlyBtn.addEventListener('click', () => generateReport('monthly'));
    elements.downloadLatestBtn.addEventListener('click', downloadLatestReport);
    elements.reportTypeSelect.addEventListener('change', refreshLatestReportMeta);
    elements.webQueryBtn.addEventListener('click', () => {
        state.webLogs.page = 1;
        loadWebLogs();
    });
    elements.searchQueryBtn.addEventListener('click', () => {
        state.searchLogs.page = 1;
        loadSearchLogs();
    });
    elements.webPrevBtn.addEventListener('click', () => changePage(state.webLogs, -1, loadWebLogs));
    elements.webNextBtn.addEventListener('click', () => changePage(state.webLogs, 1, loadWebLogs));
    elements.searchPrevBtn.addEventListener('click', () => changePage(state.searchLogs, -1, loadSearchLogs));
    elements.searchNextBtn.addEventListener('click', () => changePage(state.searchLogs, 1, loadSearchLogs));
    elements.interfaceSelect.addEventListener('change', persistPreferences);
    elements.timeLimitInput.addEventListener('change', persistPreferences);

    initialize();

    async function initialize() {
        await loadInterfaces();
        restorePreferences();
        await restoreRuntime();
        await refreshAllAuditViews();
        syncActionAvailability();
    }

    async function loadInterfaces() {
        setInterfacePlaceholder('加载中...');
        try {
            const interfaces = await fetchJSON('/api/interfaces');
            const previousValue = elements.interfaceSelect.value;
            elements.interfaceSelect.innerHTML = '';

            if (!Array.isArray(interfaces) || interfaces.length === 0) {
                setInterfacePlaceholder('No interfaces available');
                updateRunState(false, 'No interfaces available');
                return;
            }

            interfaces.forEach((iface) => {
                const option = document.createElement('option');
                option.value = iface.rawName;
                option.textContent = iface.name;
                elements.interfaceSelect.appendChild(option);
            });

            if (previousValue && interfaces.some((iface) => iface.rawName === previousValue)) {
                elements.interfaceSelect.value = previousValue;
            } else {
                elements.interfaceSelect.selectedIndex = 0;
            }
            syncActionAvailability();
        } catch (error) {
            console.error('load interfaces failed', error);
            setInterfacePlaceholder('加载失败');
            updateRunState(false, '加载失败');
        }
    }

    async function restoreRuntime() {
        try {
            if (!state.managedPage) {
                console.error('managed task runtime client is unavailable');
                return;
            }
            await state.managedPage.restoreRuntime({
                onInactive: () => {
                    updateRunState(false, 'Not running');
                },
                onCommand: restoreCommandFields,
                onResume: () => {
                    state.reconnectRequested = true;
                    updateRunState(true, 'Running in background');
                }
            });
        } catch (error) {
            console.error('restore runtime failed', error);
            updateRunState(false, 'Runtime status unavailable');
        }
    }

    function restoreCommandFields(command) {
        if (command.interface) elements.interfaceSelect.value = command.interface;
        if (command.limit) elements.timeLimitInput.value = command.limit;
    }

    function restorePreferences() {
        const saved = loadJSONStorage(
            STORAGE_KEY,
            null,
            (error) => console.error('restore preferences failed', error)
        );
        if (!saved) return;
        if (saved.interface) elements.interfaceSelect.value = saved.interface;
        if (saved.limit) elements.timeLimitInput.value = saved.limit;
    }

    function persistPreferences() {
        saveJSONStorage(
            STORAGE_KEY,
            {
                interface: elements.interfaceSelect.value,
                limit: elements.timeLimitInput.value
            },
            (error) => console.error('persist preferences failed', error)
        );
    }

    function loadAISettings() {
        return loadJSONStorage(
            'ai_settings',
            { provider: 'ollama', apiKey: '', apiBase: '', model: 'deepseek-r1:8b' },
            (error) => console.error('load ai settings failed', error)
        );
    }

    function startAnalysis() {
        const iface = elements.interfaceSelect.value;
        if (!iface) {
            alert('请先选择网卡');
            return;
        }

        persistPreferences();
        const aiSettings = loadAISettings();
        state.pendingStartPayload = {
            action: 'start',
            interface: iface,
            limit: elements.timeLimitInput.value,
            provider: aiSettings.provider,
            apiKey: aiSettings.apiKey,
            apiBase: aiSettings.apiBase,
            model: aiSettings.model
        };
        state.reconnectRequested = true;
        updateRunState(true, '正在启动...');
        ensureSocket();

        if (sendSocketPayload(state.pendingStartPayload)) {
            state.pendingStartPayload = null;
        }
    }

    function stopAnalysis() {
        state.reconnectRequested = false;
        state.pendingStartPayload = null;
        sendSocketPayload({ action: 'stop' });
        updateRunState(false, 'Stopped');
    }

    function handleReportSocketError(error, context) {
        if (context && context.phase === 'parse') {
            console.error('parse websocket message failed', error, context.raw);
            return;
        }

        updateRunState(
            state.reconnectRequested,
            state.reconnectRequested ? '连接中断，正在重连...' : '连接已断开'
        );
    }

    function handleReportSocketClose() {
        state.socket = null;
        if (state.reconnectRequested) {
            updateRunState(true, '等待重新连接...');
            return;
        }
        updateRunState(false, 'Stopped');
    }

    function ensureSocket() {
        if (state.managedPage) {
            state.socket = state.managedPage.ensureSocket();
            return;
        }

        console.error('managed task runtime client is unavailable');
    }

    function sendSocketPayload(payload) {
        if (state.managedPage) {
            if (payload && payload.action === 'start') {
                return state.managedPage.start(payload);
            }
            if (payload && payload.action === 'stop') {
                return state.managedPage.stop(payload);
            }
            return state.managedPage.send(payload);
        }

        console.error('managed task runtime client is unavailable');
        return false;
    }

    function handleLiveMessage(message) {
        if (message.type === 'activity_log') {
            const sessions = Array.isArray(message.data) ? message.data : [];
            sessions.forEach((session) => {
                state.liveSessions.set(session.session_id, session);
            });
            while (state.liveSessions.size > MAX_LIVE_SESSIONS) {
                const oldestKey = state.liveSessions.keys().next().value;
                if (!oldestKey) break;
                state.liveSessions.delete(oldestKey);
            }
            renderLiveSessions();
            updateRunState(true, 'Collecting live data');
            return;
        }

        if (message.type === 'status' && message.message) {
            updateRunState(true, message.message);
            return;
        }

        if (message.type === 'error' && message.message) {
            updateRunState(false, message.message);
        }
    }

    function renderLiveSessions() {
        const sessions = Array.from(state.liveSessions.values())
            .sort((left, right) => String(right.captured_at || '').localeCompare(String(left.captured_at || '')))
            .slice(0, 12);

        if (!sessions.length) {
            elements.liveSessions.innerHTML = '<div class="empty-box">暂无实时会话，等待新的行为数据</div>';
            return;
        }

        elements.liveSessions.innerHTML = sessions.map((session) => {
            const severityClass = severityPillClass(session.risk_level);
            const behaviorChain = Array.isArray(session.behavior_chain) ? session.behavior_chain.join(' -> ') : '';
            return `
                <div class="live-card">
                    <div class="live-card-header">
                        <div>
                            <div class="live-card-title">${escapeHTML(session.app_name || session.main_service || session.domain || '未命名')}</div>
                            <div class="muted">${escapeHTML(session.full_host || session.domain || '-')} | ${escapeHTML(session.src_ip || '-')}</div>
                        </div>
                        <span class="pill ${severityClass}">${escapeHTML(String(session.risk_score || 0))} / ${escapeHTML(session.risk_level || 'low')}</span>
                    </div>
                    <div class="muted">${escapeHTML(behaviorChain || session.behavior_label || 'Analyzing session')}</div>
                    <div class="live-card-meta">
                        <span class="mini-chip">${escapeHTML(session.category || 'Uncategorized')}</span>
                        <span class="mini-chip">${escapeHTML(session.productivity_category || 'Neutral')}</span>
                        <span class="mini-chip">${escapeHTML(formatBytes(session.bytes || 0))}</span>
                        <span class="mini-chip">请求 ${escapeHTML(String(session.request_count || 0))}</span>
                        <span class="mini-chip">证据 ${escapeHTML(session.evidence_level || '-')}</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    async function refreshAllAuditViews() {
        await Promise.all([
            loadWebLogs(),
            loadSearchLogs(),
            loadTopSites(),
            loadTopApps(),
            loadViolationStats(),
            refreshLatestReportMeta()
        ]);
    }

    async function loadWebLogs() {
        await loadPagedAuditData({
            endpoint: '/api/audit/web-logs',
            pagingState: state.webLogs,
            pageInfo: elements.webPageInfo,
            render: renderWebLogs,
            onError: () => {
                elements.webLogBody.innerHTML = renderTableEmpty('网页日志加载失败', 7);
            },
            params: {
                start: toApiTime(elements.webStart.value),
                end: toApiTime(elements.webEnd.value),
                src_ip: elements.webSrcIP.value.trim(),
                domain: elements.webDomain.value.trim(),
                category: elements.webCategory.value
            }
        });
    }

    async function loadSearchLogs() {
        await loadPagedAuditData({
            endpoint: '/api/audit/search-logs',
            pagingState: state.searchLogs,
            pageInfo: elements.searchPageInfo,
            render: renderSearchLogs,
            onError: () => {
                elements.searchLogBody.innerHTML = renderTableEmpty('搜索日志加载失败', 6);
            },
            params: {
                start: toApiTime(elements.searchStart.value),
                end: toApiTime(elements.searchEnd.value),
                src_ip: elements.searchSrcIP.value.trim(),
                engine: elements.searchEngine.value,
                keyword: elements.searchKeyword.value.trim()
            }
        });
    }

    async function loadPagedAuditData({ endpoint, pagingState, pageInfo, render, onError, params: filterParams }) {
        const params = buildPagedParams(pagingState, filterParams);
        try {
            const payload = await fetchJSON(`${endpoint}?${params.toString()}`);
            pagingState.total = Number(payload.total || 0);
            render(Array.isArray(payload.items) ? payload.items : []);
        } catch (error) {
            console.error(`load ${endpoint} failed`, error);
            pagingState.total = 0;
            onError();
        } finally {
            renderPageInfo(pageInfo, pagingState);
        }
    }

    function buildPagedParams(pagingState, filterParams) {
        const params = new URLSearchParams({
            page: String(pagingState.page),
            pageSize: String(pagingState.pageSize)
        });
        Object.entries(filterParams).forEach(([key, value]) => appendIfPresent(params, key, value));
        return params;
    }

    async function loadTopSites() {
        try {
            const payload = await fetchJSON('/api/audit/top-sites?limit=10');
            renderBarList(elements.topSites, payload.items || [], (item) => item.domain, (item) => item.request_count, (item) => `${item.request_count} 请求`);
        } catch (error) {
            console.error('load top sites failed', error);
            elements.topSites.innerHTML = '<div class="empty-box">暂无 Top 站点</div>';
        }
    }

    async function loadTopApps() {
        try {
            const payload = await fetchJSON('/api/audit/top-apps?limit=10');
            renderBarList(
                elements.topApps,
                payload.items || [],
                (item) => `${item.app_name} / ${item.category}`,
                (item) => item.request_count,
                (item) => `${item.request_count} 请求`
            );
        } catch (error) {
            console.error('load top apps failed', error);
            elements.topApps.innerHTML = '<div class="empty-box">暂无 Top 应用</div>';
        }
    }

    async function loadViolationStats() {
        try {
            const payload = await fetchJSON('/api/audit/violations/stats');
            elements.violationTotal.textContent = String(payload.total || 0);
            renderBarList(elements.violationTypes, payload.byType || [], (item) => item.name, (item) => item.count, (item) => `${item.count} times`);
            renderBarList(elements.violationSeverity, payload.bySeverity || [], (item) => item.name, (item) => item.count, (item) => `${item.count} times`);
            renderViolationTable(payload.recent || []);
        } catch (error) {
            console.error('load violation stats failed', error);
            elements.violationBody.innerHTML = renderTableEmpty('违规记录加载失败', 6);
        }
    }

    async function generateReport(reportType) {
        try {
            const payload = await fetchJSON('/api/reports/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reportType })
            });
            alert(`${reportType === 'weekly' ? 'Weekly report' : 'Monthly report'} generated`);
            state.latestReport = payload;
            elements.reportTypeSelect.value = reportType;
            await refreshLatestReportMeta();
        } catch (error) {
            console.error('generate report failed', error);
            alert(`生成报告失败: ${error.message}`);
        }
    }

    async function refreshLatestReportMeta() {
        const reportType = elements.reportTypeSelect.value;
        try {
            const response = await fetch(`/api/reports/latest?reportType=${encodeURIComponent(reportType)}`);
            if (response.status === 404) {
                state.latestReport = null;
                elements.latestReportMeta.textContent = `No ${reportType === 'weekly' ? 'weekly report' : 'monthly report'} available`;
                syncActionAvailability();
                return;
            }
            const payload = await parseJSONResponse(response);
            if (!response.ok) {
                throw new Error(extractErrorMessage(payload, response.status));
            }
            state.latestReport = payload;
            elements.latestReportMeta.textContent = `Latest ${reportType === 'weekly' ? 'weekly report' : 'monthly report'}: ${payload.createdAt}, period ${payload.periodStart} ~ ${payload.periodEnd}`;
            syncActionAvailability();
        } catch (error) {
            console.error('load latest report failed', error);
            elements.latestReportMeta.textContent = 'Failed to load latest report';
            state.latestReport = null;
            syncActionAvailability();
        }
    }

    function downloadLatestReport() {
        if (!state.latestReport || !state.latestReport.downloadUrl) {
            alert('No latest report is available to download');
            return;
        }
        window.location.href = state.latestReport.downloadUrl;
    }

    function renderWebLogs(items) {
        if (!items.length) {
            elements.webLogBody.innerHTML = renderTableEmpty('暂无网页日志', 7);
            return;
        }
        elements.webLogBody.innerHTML = renderTableRows(items, (item) => [
            item.captured_at || '-',
            item.src_ip || '-',
            item.full_host || item.domain || '-',
            { html: `${escapeHTML(item.app_name || '-')}<div class="muted">${escapeHTML(item.category || '-')}</div>` },
            String(item.request_count || 0),
            formatBytes(item.bytes || 0),
            item.evidence_level || '-'
        ]);
    }

    function renderSearchLogs(items) {
        if (!items.length) {
            elements.searchLogBody.innerHTML = renderTableEmpty('暂无搜索日志', 6);
            return;
        }
        elements.searchLogBody.innerHTML = renderTableRows(items, (item) => [
            item.captured_at || '-',
            item.src_ip || '-',
            item.domain || '-',
            item.engine || '-',
            item.keyword || '-',
            item.evidence_level || '-'
        ]);
    }

    function renderViolationTable(items) {
        if (!items.length) {
            elements.violationBody.innerHTML = renderTableEmpty('暂无违规记录', 6);
            return;
        }
        elements.violationBody.innerHTML = renderTableRows(items, (item) => [
            item.captured_at || '-',
            item.src_ip || '-',
            item.domain || '-',
            item.violation_type || '-',
            { html: `<span class="pill ${severityPillClass(item.severity)}">${escapeHTML(item.severity || '-')}</span>` },
            item.reason || '-'
        ]);
    }

    function renderTableRows(items, rowFn) {
        return items.map((item) => `<tr>${rowFn(item).map(renderTableCell).join('')}</tr>`).join('');
    }

    function renderTableCell(value) {
        if (value && typeof value === 'object' && typeof value.html === 'string') {
            return `<td>${value.html}</td>`;
        }
        return `<td>${escapeHTML(value ?? '-')}</td>`;
    }

    function renderBarList(container, items, labelFn, valueFn, suffixFn) {
        const safeItems = Array.isArray(items) ? items : [];
        if (!safeItems.length) {
            container.innerHTML = '<div class="empty-box">暂无数据</div>';
            return;
        }

        const values = safeItems.map((item) => {
            const value = Number(valueFn(item) || 0);
            return Number.isFinite(value) ? Math.max(0, value) : 0;
        });
        const maxValue = Math.max(...values, 1);
        container.innerHTML = safeItems.map((item, index) => {
            const value = values[index];
            const width = Math.max((value / maxValue) * 100, 2);
            return `
                <div class="bar-row">
                    <div class="bar-label">
                        <span>${escapeHTML(labelFn(item))}</span>
                        <span>${escapeHTML(suffixFn(item))}</span>
                    </div>
                    <div class="bar-track">
                        <div class="bar-fill" style="width:${width}%"></div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function renderPageInfo(target, pagingState) {
        const totalPages = Math.max(Math.ceil((pagingState.total || 0) / pagingState.pageSize), 1);
        if (pagingState.page > totalPages) pagingState.page = totalPages;
        target.textContent = `Page ${pagingState.page} / ${totalPages}, total ${pagingState.total || 0}`;
    }

    function changePage(pagingState, delta, callback) {
        const totalPages = Math.max(Math.ceil((pagingState.total || 0) / pagingState.pageSize), 1);
        const nextPage = pagingState.page + delta;
        if (nextPage < 1 || nextPage > totalPages) return;
        pagingState.page = nextPage;
        callback();
    }

    function updateRunState(isRunning, statusText) {
        state.isRunning = isRunning;
        elements.timeLimitInput.disabled = isRunning;
        elements.liveStatus.textContent = statusText;
        syncActionAvailability();
    }

    function syncActionAvailability() {
        const hasInterface = Array.from(elements.interfaceSelect.options).some((option) => option.value) && Boolean(elements.interfaceSelect.value);
        elements.startBtn.disabled = state.isRunning || !hasInterface;
        elements.stopBtn.disabled = !state.isRunning;
        elements.interfaceSelect.disabled = state.isRunning || !Array.from(elements.interfaceSelect.options).some((option) => option.value);
        elements.downloadLatestBtn.disabled = !state.latestReport || !state.latestReport.downloadUrl;
    }

    function setInterfacePlaceholder(label) {
        elements.interfaceSelect.innerHTML = `<option value="">${escapeHTML(label)}</option>`;
        elements.interfaceSelect.value = '';
        syncActionAvailability();
    }

    function appendIfPresent(params, key, value) {
        if (value) params.set(key, value);
    }

    function renderTableEmpty(message, colspan = 7) {
        return `<tr><td colspan="${colspan}" class="muted">${escapeHTML(message)}</td></tr>`;
    }

    function toApiTime(value) {
        if (!value) return '';
        const normalized = value.replace('T', ' ');
        return normalized.length === 16 ? `${normalized}:00` : normalized;
    }

    function severityPillClass(level) {
        const normalized = String(level || '').toLowerCase();
        if (normalized === 'high') return 'pill-high';
        if (normalized === 'medium') return 'pill-medium';
        return 'pill-low';
    }

    function formatBytes(value) {
        const bytes = Number(value || 0);
        if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let current = bytes;
        let index = 0;
        while (current >= 1024 && index < units.length - 1) {
            current /= 1024;
            index += 1;
        }
        return `${current.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
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

    async function fetchJSON(url, options) {
        const response = await fetch(url, options);
        const payload = await parseJSONResponse(response);
        if (!response.ok) {
            throw new Error(extractErrorMessage(payload, response.status));
        }
        return payload || {};
    }

    async function parseJSONResponse(response) {
        const text = await response.text();
        if (!text) return null;
        try {
            return JSON.parse(text);
        } catch (error) {
            throw new Error(text || `HTTP ${response.status}`);
        }
    }

    function extractErrorMessage(payload, status) {
        if (payload && typeof payload === 'object') {
            if (typeof payload.error === 'string' && payload.error.trim()) return payload.error.trim();
            if (typeof payload.message === 'string' && payload.message.trim()) return payload.message.trim();
        }
        if (typeof payload === 'string' && payload.trim()) return payload.trim();
        return `HTTP ${status}`;
    }
});
