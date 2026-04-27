document.addEventListener('DOMContentLoaded', () => {
    const STORAGE_KEY = 'threat_capture_preferences';
    const runtimeClient = window.SecflowTaskRuntime || {};
    const createManagedTaskPage = runtimeClient.createManagedTaskPage;
    const escapeHTML = runtimeClient.escapeHTML || fallbackEscapeHTML;
    const loadJSONStorage = runtimeClient.loadJSONStorage || fallbackLoadJSONStorage;
    const saveJSONStorage = runtimeClient.saveJSONStorage || fallbackSaveJSONStorage;
    const elements = {
        interfaceSelect: document.getElementById('interface-select'),
        packetCount: document.getElementById('packet-count'),
        portFilter: document.getElementById('port-filter'),
        customPortGroup: document.getElementById('custom-port-group'),
        customPort: document.getElementById('custom-port'),
        startBtn: document.getElementById('start-btn'),
        stopBtn: document.getElementById('stop-btn'),
        captureStatus: document.getElementById('capture-status'),
        packetsCaptured: document.getElementById('packets-captured'),
        tableBody: document.getElementById('packet-table-body'),
        emptyState: document.getElementById('empty-state'),
        modal: document.getElementById('detail-modal'),
        closeModal: document.querySelector('.close-modal'),
        modalId: document.getElementById('modal-id'),
        modalAnalysis: document.getElementById('modal-analysis'),
        modalRawData: document.getElementById('modal-raw-data'),
        summarySection: document.getElementById('summary-section')
    };

    if (!elements.startBtn || !elements.tableBody) return;

    let socket = null;
    let chart = null;
    let packetStorage = {};
    let counter = 0;
    let pendingStartPayload = null;
    let reconnectRequested = false;
    const managedPage = createManagedTaskPage ? createManagedTaskPage({
        runtimePath: '/api/runtime/threat',
        wsPath: '/ws/capture',
        reconnectMs: 1200,
        onSocketOpen: (_event, activeSocket) => {
            socket = activeSocket;
        },
        onMessage: handleCaptureSocketMessage,
        onError: handleCaptureSocketError,
        onSocketClose: handleCaptureSocketClose
    }) : null;

    elements.startBtn.addEventListener('click', startCapture);
    elements.stopBtn.addEventListener('click', stopCapture);
    elements.closeModal.onclick = () => elements.modal.style.display = 'none';

    window.onclick = (event) => {
        if (event.target === elements.modal) {
            elements.modal.style.display = 'none';
        }
    };

    elements.portFilter.addEventListener('change', () => {
        elements.customPortGroup.style.display = elements.portFilter.value === 'custom' ? 'flex' : 'none';
    });

    window.openDetail = openDetail;

    initialize();

    async function initialize() {
        await loadInterfaces();
        restorePreferences();
        await restoreRunningCapture();
    }

    async function loadInterfaces() {
        try {
            const response = await fetch('/api/interfaces');
            const interfaces = await response.json();
            elements.interfaceSelect.innerHTML = '';

            if (interfaces && interfaces.length > 0) {
                interfaces.forEach((iface) => {
                    const option = document.createElement('option');
                    option.value = iface.rawName;
                    option.textContent = iface.name;
                    elements.interfaceSelect.appendChild(option);
                });
                elements.interfaceSelect.disabled = false;
            } else {
                elements.interfaceSelect.innerHTML = '<option>未找到网卡</option>';
            }
        } catch (error) {
            elements.interfaceSelect.innerHTML = '<option>加载失败</option>';
        }
    }

    async function restoreRunningCapture() {
        try {
            const restoreOptions = {
                onCommand: restoreCommandFields,
                onResume: (runtime) => {
                    reconnectRequested = true;
                    resetCaptureView();
                    updateState(true, 'Running, reconnected');
                    if (!runtime.active) {
                        updateState(true, 'Task is recovering, session reconnected');
                    }
                }
            };
            if (managedPage) {
                await managedPage.restoreRuntime(restoreOptions);
                return;
            }
            console.error('managed task runtime client is unavailable');
        } catch (error) {
            console.error('restore runtime failed', error);
        }
    }

    function restoreCommandFields(command) {
        if (command.interface) {
            elements.interfaceSelect.value = command.interface;
        }
        if (command.count) {
            elements.packetCount.value = command.count;
        }
        if (command.port) {
            const builtInPort = ['80', '443'].includes(command.port) ? command.port : 'custom';
            elements.portFilter.value = builtInPort;
            if (builtInPort === 'custom') {
                elements.customPort.value = command.port;
                elements.customPortGroup.style.display = 'flex';
            }
        }
        persistPreferences();
    }

    function startCapture() {
        const iface = elements.interfaceSelect.value;
        const count = elements.packetCount.value;
        let port = elements.portFilter.value;

        if (!iface) return;
        if (port === 'custom') port = elements.customPort.value;

        persistPreferences();

        const aiSettings = loadAISettings();
        pendingStartPayload = {
            action: 'start',
            interface: iface,
            count: count,
            port: port,
            provider: aiSettings.provider,
            apiKey: aiSettings.apiKey,
            apiBase: aiSettings.apiBase,
            model: aiSettings.model
        };

        reconnectRequested = true;
        resetCaptureView();
        updateState(true, '正在启动...');
        if (managedPage) {
            managedPage.start(pendingStartPayload);
            pendingStartPayload = null;
            return;
        }
        if (sendSocketPayload(pendingStartPayload)) {
            pendingStartPayload = null;
        }
        ensureSocket();
    }

    function stopCapture() {
        reconnectRequested = false;
        pendingStartPayload = null;

        if (managedPage) {
            managedPage.stop({ action: 'stop' });
        } else {
            sendSocketPayload({ action: 'stop' });
        }

        updateState(false, '正在停止...');
    }

    function handleCaptureSocketMessage(data) {
        if (data.type === 'task_finished') {
            reconnectRequested = false;
            if (managedPage) {
                managedPage.setReconnectRequested(false);
            }
            updateState(false, 'Task finished');
            renderSummaryGraph();
            return;
        }

        if (data.type === 'packet_event' && data.payload) {
            addPacketRow(data.payload);
            updateState(true, '正在抓包...');
            return;
        }

        if (data.type === 'status' && data.message) {
            updateState(true, data.message);
        } else if (data.level === 'warning' && data.message) {
            updateState(true, data.message);
        } else if (data.type === 'error' && data.message) {
            updateState(false, data.message);
        }
    }

    function handleCaptureSocketError(_error, context) {
        if (context && context.phase === 'parse') {
            console.log('raw message', context.raw);
            return;
        }

        if (!reconnectRequested) {
            updateState(false, '连接异常');
        }
    }

    function handleCaptureSocketClose() {
        socket = null;
        if (!reconnectRequested && !pendingStartPayload) {
            updateState(false, '已停止');
        }
    }

    function ensureSocket() {
        if (managedPage) {
            socket = managedPage.ensureSocket();
            return;
        }
        console.error('managed task runtime client is unavailable');
    }

    function sendSocketPayload(payload) {
        if (managedPage) {
            return managedPage.send(payload);
        }
        console.error('managed task runtime client is unavailable');
        return false;
    }

    function resetCaptureView() {
        counter = 0;
        packetStorage = {};
        elements.tableBody.innerHTML = '';
        elements.packetsCaptured.textContent = '0';
        elements.emptyState.style.display = 'none';
        elements.summarySection.style.display = 'none';
    }

    function addPacketRow(data) {
        if (packetStorage[data.id]) {
            return;
        }

        packetStorage[data.id] = data;
        counter += 1;
        elements.packetsCaptured.textContent = counter;

        const analysis = data.analysis || {};
        const isThreat = analysis.is_threat === true || String(analysis.is_threat) === 'true';
        const row = document.createElement('tr');
        const time = new Date((data.timestamp || 0) * 1000).toLocaleTimeString();
        const src = data.src === 'N/A' ? '<span style="color:#565f89">非 IPv4</span>' : escapeHTML(data.src || '-');
        const dst = data.dst === 'N/A' ? '-' : escapeHTML(data.dst || '-');
        const badge = isThreat
            ? `<span class="badge badge-danger">风险 ${escapeHTML(analysis.threat_type || '未知')}</span>`
            : '<span class="badge badge-safe">正常</span>';

        if (isThreat) {
            row.classList.add('table-danger-row');
        }

        row.innerHTML = `
            <td>${data.id}</td>
            <td>${time}</td>
            <td>${src}</td>
            <td>${dst}</td>
            <td>${escapeHTML(data.proto || 'L2')}</td>
            <td>${badge}</td>
            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #787c99;">
                ${escapeHTML(data.packet_details?.summary || '')}
            </td>
            <td><button class="btn-detail" onclick="window.openDetail(${data.id})">详情</button></td>
        `;

        elements.tableBody.insertBefore(row, elements.tableBody.firstChild);
    }

    function updateState(isRunning, message) {
        elements.startBtn.disabled = isRunning;
        elements.stopBtn.disabled = !isRunning;
        elements.interfaceSelect.disabled = isRunning;
        elements.captureStatus.textContent = message || (isRunning ? '运行中...' : '待机');
        elements.captureStatus.className = isRunning ? 'status-value active' : 'status-value';
    }

    function openDetail(id) {
        const data = packetStorage[id];
        if (!data) return;

        const analysis = data.analysis || {};
        const isThreat = analysis.is_threat === true || String(analysis.is_threat) === 'true';
        elements.modalId.textContent = id;
        elements.modalAnalysis.innerHTML = `
            <div style="margin-bottom:15px">
                <span class="badge ${isThreat ? 'badge-danger' : 'badge-safe'}" style="font-size:1em; padding:8px 12px">
                    ${isThreat ? '检测到威胁' : '未发现威胁'}
                </span>
            </div>
            <p><strong>Type:</strong> ${escapeHTML(analysis.threat_type || 'none')}</p>
            <p><strong>Summary:</strong> ${escapeHTML(analysis.summary || 'none')}</p>
            <div style="margin-top:15px; padding:10px; background:rgba(0,0,0,0.2); border-radius:4px">
                <strong style="color:#bb9af7">Reason:</strong><br>${escapeHTML(analysis.reason || 'none')}
            </div>
        `;
        elements.modalRawData.textContent = JSON.stringify(data.packet_details || {}, null, 2);
        elements.modal.style.display = 'block';
    }

    function loadAISettings() {
        return loadJSONStorage(
            'ai_settings',
            { provider: 'ollama', apiKey: '', apiBase: '', model: 'deepseek-r1:8b' },
            (error) => console.error('load ai settings failed', error)
        );
    }

    function restorePreferences() {
        const preferences = loadJSONStorage(
            STORAGE_KEY,
            null,
            (error) => console.error('restore threat preferences failed', error)
        );
        if (!preferences) return;
        if (preferences.interface) elements.interfaceSelect.value = preferences.interface;
        if (preferences.count) elements.packetCount.value = preferences.count;
        if (preferences.port) {
            if (['80', '443'].includes(preferences.port)) {
                elements.portFilter.value = preferences.port;
            } else {
                elements.portFilter.value = 'custom';
                elements.customPort.value = preferences.port;
                elements.customPortGroup.style.display = 'flex';
            }
        }
    }

    function persistPreferences() {
        let port = elements.portFilter.value;
        if (port === 'custom') {
            port = elements.customPort.value;
        }

        saveJSONStorage(STORAGE_KEY, {
            interface: elements.interfaceSelect.value,
            count: elements.packetCount.value,
            port: port || ''
        }, (error) => console.error('persist threat preferences failed', error));
    }

    function initChart() {
        chart = echarts.init(document.getElementById('summary-graph'));
        window.addEventListener('resize', () => {
            if (chart) chart.resize();
        });
    }

    function renderSummaryGraph() {
        const packets = Object.values(packetStorage);
        if (!packets.length) return;

        elements.summarySection.style.display = 'block';

        if (!chart) {
            initChart();
        } else {
            chart.resize();
        }

        const connections = {};
        const nodesInfo = {};
        let maxInternalCount = 0;
        let localHostIP = '';

        packets.forEach((packet) => {
            const src = packet.src;
            const dst = packet.dst;
            if (src === 'N/A' || dst === 'N/A') return;

            [src, dst].forEach((ip) => {
                if (!nodesInfo[ip]) nodesInfo[ip] = { count: 0 };
                nodesInfo[ip].count += 1;

                if (isInternalIP(ip) && nodesInfo[ip].count > maxInternalCount) {
                    maxInternalCount = nodesInfo[ip].count;
                    localHostIP = ip;
                }
            });

            const pair = [src, dst].sort();
            const key = pair.join('|');
            if (!connections[key]) {
                connections[key] = { count: 0, hasThreat: false, dirs: new Set() };
            }

            connections[key].count += 1;
            if (packet.analysis?.is_threat === true || String(packet.analysis?.is_threat) === 'true') {
                connections[key].hasThreat = true;
            }
            connections[key].dirs.add(`${src}->${dst}`);
        });

        const width = chart.getWidth();
        const height = chart.getHeight();

        const nodes = Object.entries(nodesInfo).map(([ip, info]) => {
            let category = 0;
            let color = '#ef4444';
            let y = height * 0.2;

            if (isGatewayIP(ip) || ip === localHostIP) {
                category = 1;
                color = '#3b82f6';
                y = height * 0.5;
            } else if (isInternalIP(ip)) {
                category = 2;
                color = '#10b981';
                y = height * 0.8;
            }

            return {
                id: ip,
                name: ip,
                symbolSize: Math.min(20 + (info.count / packets.length) * 100, 80),
                value: info.count,
                itemStyle: { color },
                category,
                x: Math.random() * (width * 0.8) + width * 0.1,
                y,
                label: {
                    show: true,
                    position: 'top',
                    color: '#1f2937',
                    backgroundColor: 'rgba(255, 255, 255, 0.9)',
                    padding: [2, 4],
                    borderRadius: 4
                }
            };
        });

        const links = Object.entries(connections).map(([key, info]) => {
            const [src, dst] = key.split('|');
            const isBiDirectional = info.dirs.has(`${src}->${dst}`) && info.dirs.has(`${dst}->${src}`);
            return {
                source: src,
                target: dst,
                lineStyle: {
                    width: Math.min(2 + info.count, 15),
                    color: info.hasThreat ? '#ef4444' : '#3b82f6',
                    type: isBiDirectional ? 'solid' : 'dashed',
                    curveness: 0.1,
                    opacity: 0.8
                },
                value: info.count
            };
        });

        chart.setOption({
            backgroundColor: '#ffffff',
            tooltip: {
                trigger: 'item',
                formatter: (point) => point.dataType === 'node'
                    ? `IP: ${point.name}<br/>连接数: ${point.value}`
                    : `流向: ${point.data.source} -> ${point.data.target}<br/>次数: ${point.data.value}`
            },
            legend: [{
                data: ['外部 IP', '网关/主机', '内部设备'],
                bottom: 20,
                textStyle: { color: '#4b5563' }
            }],
            series: [{
                type: 'graph',
                layout: 'force',
                data: nodes,
                links: links,
                categories: [{ name: '外部 IP' }, { name: '网关/主机' }, { name: '内部设备' }],
                roam: true,
                draggable: true,
                force: {
                    repulsion: 1000,
                    edgeLength: [50, 200],
                    gravity: 0.05
                },
                emphasis: { focus: 'adjacency', lineStyle: { width: 10 } }
            }]
        });
    }

    function isInternalIP(ip) {
        if (!ip || ip === 'N/A') return false;
        return ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '127.0.0.1';
    }

    function isGatewayIP(ip) {
        if (!ip || ip === 'N/A') return false;
        return ip.endsWith('.1') || ip.endsWith('.254');
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

    elements.interfaceSelect.addEventListener('change', persistPreferences);
    elements.packetCount.addEventListener('change', persistPreferences);
    elements.portFilter.addEventListener('change', persistPreferences);
    elements.customPort.addEventListener('change', persistPreferences);
});
