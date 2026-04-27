(function () {
    function escapeHTML(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function createTaskSocket(options) {
        const settings = options || {};
        const reconnectMs = Number.isFinite(settings.reconnectMs) ? settings.reconnectMs : 1200;
        const parseJSON = settings.parseJSON !== false;
        let socket = null;
        let reconnectTimer = null;
        let manualClose = false;

        function clearReconnectTimer() {
            if (reconnectTimer) {
                clearTimeout(reconnectTimer);
                reconnectTimer = null;
            }
        }

        function shouldReconnect() {
            return !manualClose &&
                typeof settings.shouldReconnect === 'function' &&
                settings.shouldReconnect();
        }

        function notifyError(error, context) {
            if (typeof settings.onError === 'function') {
                settings.onError(error, context);
            }
        }

        function buildSocketURL() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            return `${protocol}//${window.location.host}${settings.wsPath}`;
        }

        function ensureConnected() {
            manualClose = false;
            if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
                return socket;
            }

            clearReconnectTimer();
            socket = new WebSocket(buildSocketURL());

            socket.onopen = function (event) {
                clearReconnectTimer();
                if (typeof settings.onOpen === 'function') {
                    settings.onOpen(event, socket);
                }
            };

            socket.onmessage = function (event) {
                if (typeof settings.onMessage !== 'function') {
                    return;
                }

                let message = event.data;
                if (parseJSON) {
                    try {
                        message = JSON.parse(event.data);
                    } catch (error) {
                        notifyError(error, {
                            phase: 'parse',
                            raw: event.data,
                            event,
                            socket
                        });
                        return;
                    }
                }

                settings.onMessage(message, event, socket);
            };

            socket.onerror = function (event) {
                notifyError(event, {
                    phase: 'socket',
                    event,
                    socket
                });
            };

            socket.onclose = function (event) {
                const closedSocket = socket;
                socket = null;

                if (typeof settings.onClose === 'function') {
                    settings.onClose(event, closedSocket);
                }

                if (!shouldReconnect()) {
                    return;
                }

                reconnectTimer = setTimeout(function () {
                    reconnectTimer = null;
                    if (typeof settings.onReconnect === 'function') {
                        settings.onReconnect();
                    }
                    if (shouldReconnect()) {
                        ensureConnected();
                    }
                }, reconnectMs);
            };

            return socket;
        }

        function isOpen() {
            return !!socket && socket.readyState === WebSocket.OPEN;
        }

        function isConnecting() {
            return !!socket && socket.readyState === WebSocket.CONNECTING;
        }

        function sendJSON(value) {
            if (!isOpen()) {
                return false;
            }
            socket.send(JSON.stringify(value));
            return true;
        }

        function close() {
            manualClose = true;
            clearReconnectTimer();
            if (!socket) {
                return;
            }

            const activeSocket = socket;
            socket = null;
            activeSocket.close();
        }

        function getSocket() {
            return socket;
        }

        return {
            close,
            ensureConnected,
            getSocket,
            isConnecting,
            isOpen,
            sendJSON
        };
    }

    async function restoreTaskRuntime(options) {
        const settings = options || {};
        if (!settings.runtimePath) {
            throw new Error('runtimePath is required');
        }

        const response = await fetch(settings.runtimePath);
        if (!response.ok) {
            if (typeof settings.onUnavailable === 'function') {
                settings.onUnavailable(response);
            }
            return {
                resumed: false,
                runtime: null,
                command: {}
            };
        }

        const runtime = await response.json();
        const command = runtime.lastCommand || {};
        const shouldResume = typeof settings.shouldResume === 'function'
            ? settings.shouldResume(runtime, command)
            : runtime.active || runtime.desiredState === 'running';

        if (!shouldResume) {
            if (typeof settings.onInactive === 'function') {
                settings.onInactive(runtime, command);
            }
            return {
                resumed: false,
                runtime,
                command
            };
        }

        if (typeof settings.onCommand === 'function') {
            settings.onCommand(command, runtime);
        }
        if (typeof settings.onResume === 'function') {
            settings.onResume(runtime, command);
        }

        return {
            resumed: true,
            runtime,
            command
        };
    }

    function loadJSONStorage(key, fallbackValue, onError) {
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

    function saveJSONStorage(key, value, onError) {
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

    function createManagedTaskPage(options) {
        const settings = options || {};
        if (!settings.runtimePath) {
            throw new Error('runtimePath is required');
        }
        if (!settings.wsPath) {
            throw new Error('wsPath is required');
        }

        const state = {
            pendingStartPayload: null,
            reconnectRequested: false,
            socket: null
        };

        const socketClient = createTaskSocket({
            wsPath: settings.wsPath,
            reconnectMs: settings.reconnectMs,
            parseJSON: settings.parseJSON,
            shouldReconnect: () => state.reconnectRequested,
            onOpen: (event, socket) => {
                state.socket = socket;
                if (typeof settings.onSocketOpen === 'function') {
                    settings.onSocketOpen(event, socket, state);
                }
                if (state.pendingStartPayload) {
                    socketClient.sendJSON(state.pendingStartPayload);
                    state.pendingStartPayload = null;
                }
            },
            onMessage: (message, event, socket) => {
                if (typeof settings.onMessage === 'function') {
                    settings.onMessage(message, event, socket, state);
                }
            },
            onError: (error, context) => {
                if (typeof settings.onError === 'function') {
                    settings.onError(error, context, state);
                }
            },
            onClose: (event, socket) => {
                state.socket = null;
                if (typeof settings.onSocketClose === 'function') {
                    settings.onSocketClose(event, socket, state);
                }
            },
            onReconnect: () => {
                if (typeof settings.onReconnect === 'function') {
                    settings.onReconnect(state);
                }
            }
        });

        async function restoreRuntime(extraOptions) {
            const restoreOptions = Object.assign({}, settings.restoreOptions || {}, extraOptions || {}, {
                runtimePath: settings.runtimePath
            });
            const originalOnResume = restoreOptions.onResume;
            restoreOptions.onResume = (runtime, command) => {
                state.reconnectRequested = true;
                if (typeof originalOnResume === 'function') {
                    originalOnResume(runtime, command, state);
                }
                ensureSocket();
            };
            return restoreTaskRuntime(restoreOptions);
        }

        function ensureSocket() {
            state.socket = socketClient.ensureConnected();
            return state.socket;
        }

        function start(payload) {
            state.pendingStartPayload = payload;
            state.reconnectRequested = true;
            ensureSocket();
            if (socketClient.sendJSON(state.pendingStartPayload)) {
                state.pendingStartPayload = null;
                return true;
            }
            return false;
        }

        function stop(payload) {
            state.reconnectRequested = false;
            state.pendingStartPayload = null;
            return socketClient.sendJSON(payload || { action: 'stop' });
        }

        function send(payload) {
            return socketClient.sendJSON(payload);
        }

        function setReconnectRequested(value) {
            state.reconnectRequested = !!value;
        }

        function pendingStartPayload() {
            return state.pendingStartPayload;
        }

        return {
            ensureSocket,
            getState: () => state,
            pendingStartPayload,
            restoreRuntime,
            send,
            setReconnectRequested,
            socketClient,
            start,
            stop
        };
    }

    window.SecflowTaskRuntime = Object.assign({}, window.SecflowTaskRuntime, {
        createManagedTaskPage,
        createTaskSocket,
        escapeHTML,
        loadJSONStorage,
        restoreTaskRuntime,
        saveJSONStorage
    });
}());
