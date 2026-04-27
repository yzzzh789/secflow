/**
 * AI Settings Page
 */

document.addEventListener('DOMContentLoaded', () => {
    const STORAGE_KEY = 'ai_settings';
    const DEFAULT_MODELS = {
        'ollama': 'deepseek-r1:8b',
        'openai': 'gpt-3.5-turbo',
        'deepseek': 'deepseek-chat',
        'nvidia': 'meta/llama3-70b-instruct',
        'custom': ''
    };
    const DEFAULT_BASES = {
        'ollama': 'http://localhost:11434',
        'openai': 'https://api.openai.com/v1',
        'deepseek': 'https://api.deepseek.com/v1',
        'nvidia': 'https://integrate.api.nvidia.com/v1',
        'custom': 'http://localhost:8080/v1'
    };
    const BASE_HINTS = {
        'ollama': 'Ollama 默认地址为 http://localhost:11434',
        'openai': '默认使用官方地址，可替换为代理地址',
        'deepseek': '默认使用官方地址，可替换为代理地址',
        'nvidia': '默认使用官方地址，可替换为代理地址',
        'custom': '输入兼容 OpenAI API 格式的服务器地址'
    };
    const MODEL_HINTS = {
        'ollama': '推荐模型：deepseek-r1:8b, llama3',
        'openai': '推荐模型：gpt-3.5-turbo, gpt-4',
        'deepseek': '推荐模型：deepseek-chat, deepseek-reasoner',
        'nvidia': '推荐模型：meta/llama3-70b-instruct',
        'custom': '输入服务器支持的模型名称'
    };

    const providerGrid = document.getElementById('provider-grid');
    const providerOptions = document.querySelectorAll('.provider-option');
    const apiKeyGroup = document.getElementById('api-key-group');
    const apiBaseGroup = document.getElementById('api-base-group');
    const apiKeyInput = document.getElementById('api-key');
    const apiBaseInput = document.getElementById('api-base');
    const modelInput = document.getElementById('model-name');
    const apiBaseHint = document.getElementById('api-base-hint');
    const modelHint = document.getElementById('model-hint');
    const testBtn = document.getElementById('test-btn');
    const saveBtn = document.getElementById('save-btn');
    const testResult = document.getElementById('test-result');

    let currentProvider = 'ollama';

    function init() {
        loadSettings();
        bindEvents();
        updateUI();
    }

    function bindEvents() {
        providerOptions.forEach(opt => {
            opt.addEventListener('click', () => {
                const provider = opt.dataset.provider;
                selectProvider(provider);
            });
        });

        testBtn.addEventListener('click', testConnection);
        saveBtn.addEventListener('click', saveSettings);
    }

    function selectProvider(provider) {
        currentProvider = provider;

        // 更新 UI 激活状态
        providerOptions.forEach(opt => {
            opt.classList.toggle('active', opt.dataset.provider === provider);
        });

        // 更新占位符和默认值
        modelInput.placeholder = DEFAULT_MODELS[provider] || '';
        modelHint.textContent = MODEL_HINTS[provider] || '';

        // 显示/隐藏条件字段
        const needsApiKey = ['openai', 'deepseek', 'nvidia', 'custom'].includes(provider);
        const needsApiBase = true;

        apiKeyGroup.classList.toggle('visible', needsApiKey);
        apiBaseGroup.classList.toggle('visible', needsApiBase);

        apiBaseInput.placeholder = DEFAULT_BASES[provider] || '';
        apiBaseHint.textContent = BASE_HINTS[provider] || '';

        hideTestResult();
    }

    async function testConnection() {
        testBtn.disabled = true;
        testBtn.textContent = '⏳ 测试中...';
        hideTestResult();

        const config = {
            provider: currentProvider,
            apiKey: apiKeyInput.value.trim(),
            apiBase: apiBaseInput.value.trim(),
            model: modelInput.value.trim() || DEFAULT_MODELS[currentProvider]
        };

        try {
            const response = await fetch('/api/test-ai', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });

            const result = await response.json();
            showTestResult(result.success, result.message);
        } catch (error) {
            showTestResult(false, '无法连接到服务器');
        } finally {
            testBtn.disabled = false;
            testBtn.textContent = '🔌 测试连接';
        }
    }

    function showTestResult(success, message) {
        testResult.className = 'test-result ' + (success ? 'success' : 'error');
        testResult.querySelector('.icon').textContent = success ? '✅' : '❌';
        testResult.querySelector('.message').textContent = message;
    }

    function hideTestResult() {
        testResult.className = 'test-result';
    }

    function saveSettings() {
        const settings = {
            provider: currentProvider,
            apiKey: apiKeyInput.value.trim(),
            apiBase: apiBaseInput.value.trim(),
            model: modelInput.value.trim() || DEFAULT_MODELS[currentProvider]
        };

        localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));

        saveBtn.textContent = '✅ 已保存';
        saveBtn.classList.add('btn-success');
        setTimeout(() => {
            saveBtn.textContent = '💾 保存设置';
            saveBtn.classList.remove('btn-success');
        }, 2000);
    }

    function loadSettings() {
        try {
            const saved = localStorage.getItem(STORAGE_KEY);
            if (saved) {
                const settings = JSON.parse(saved);
                currentProvider = settings.provider || 'ollama';
                apiKeyInput.value = settings.apiKey || '';
                apiBaseInput.value = settings.apiBase || '';
                modelInput.value = settings.model || '';
            }
        } catch (e) {
            console.error('Failed to load settings:', e);
        }
    }

    function updateUI() {
        selectProvider(currentProvider);
    }

    window.getAISettings = function () {
        try {
            const saved = localStorage.getItem(STORAGE_KEY);
            if (saved) {
                return JSON.parse(saved);
            }
        } catch (e) { }
        return { provider: 'ollama', apiKey: '', apiBase: '', model: 'deepseek-r1:8b' };
    };

    init();
});
