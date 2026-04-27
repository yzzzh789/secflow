package app

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultHTTPPort                        = "9090"
	defaultPythonBin                       = "python"
	defaultPacketAnalyzerScript            = "./packet_analyzer/improved_packet_analyzer.py"
	defaultBehaviorAnalyzerScript          = "./scripts/traffic_analyzer.py"
	defaultLANMonitorScript                = "./scripts/lan_behavior_monitor.py"
	defaultNICMonitorScript                = "./scripts/nic_runtime.py"
	defaultWebsiteSecurityCheckConcurrency = 4
)

type runtimeConfig struct {
	ProjectRoot                     string `json:"projectRoot"`
	HTTPPort                        string `json:"httpPort"`
	Role                            string `json:"role"`
	HostAgentURL                    string `json:"hostAgentUrl"`
	ControlToken                    string `json:"-"`
	PythonBin                       string `json:"pythonBin"`
	PacketAnalyzerScript            string `json:"packetAnalyzerScript"`
	BehaviorAnalyzerScript          string `json:"behaviorAnalyzerScript"`
	LANMonitorScript                string `json:"lanMonitorScript"`
	NICMonitorScript                string `json:"nicMonitorScript"`
	PacketAnalyzerDBPath            string `json:"packetAnalyzerDbPath"`
	NICTrafficDBPath                string `json:"nicTrafficDbPath"`
	WebsiteSecurityStatePath        string `json:"websiteSecurityStatePath"`
	WebsiteSecurityCheckConcurrency int    `json:"websiteSecurityCheckConcurrency"`
}

func loadRuntimeConfig() runtimeConfig {
	root := resolveProjectRootOverride()
	httpPort := normalizeListenPort(firstEnv("SECFLOW_HTTP_PORT", "HTTP_PORT", "PORT"))

	return runtimeConfig{
		ProjectRoot:                     root,
		HTTPPort:                        httpPort,
		Role:                            normalizeRole(firstEnv("SECFLOW_ROLE")),
		HostAgentURL:                    normalizeURL(firstEnv("SECFLOW_HOST_AGENT_URL")),
		ControlToken:                    strings.TrimSpace(firstEnv("SECFLOW_CONTROL_TOKEN")),
		PythonBin:                       firstNonEmpty(firstEnv("SECFLOW_PYTHON_BIN", "PYTHON_BIN"), defaultPythonBin),
		PacketAnalyzerScript:            firstNonEmpty(firstEnv("SECFLOW_PACKET_ANALYZER_SCRIPT", "PACKET_ANALYZER_SCRIPT"), defaultPacketAnalyzerScript),
		BehaviorAnalyzerScript:          firstNonEmpty(firstEnv("SECFLOW_BEHAVIOR_ANALYZER_SCRIPT", "BEHAVIOR_ANALYZER_SCRIPT"), defaultBehaviorAnalyzerScript),
		LANMonitorScript:                firstNonEmpty(firstEnv("SECFLOW_LAN_MONITOR_SCRIPT", "LAN_MONITOR_SCRIPT"), defaultLANMonitorScript),
		NICMonitorScript:                firstNonEmpty(firstEnv("SECFLOW_NIC_MONITOR_SCRIPT", "NIC_MONITOR_SCRIPT"), defaultNICMonitorScript),
		PacketAnalyzerDBPath:            resolveRuntimePath(root, firstEnv("PACKET_ANALYZER_DB_PATH"), filepath.Join("data", "packet_analyzer.sqlite")),
		NICTrafficDBPath:                resolveRuntimePath(root, firstEnv("NIC_TRAFFIC_DB_PATH"), filepath.Join("data", "nic_traffic.sqlite")),
		WebsiteSecurityStatePath:        resolveRuntimePath(root, firstEnv("WEBSITE_SECURITY_STATE_PATH"), filepath.Join("data", "website_security_state.json")),
		WebsiteSecurityCheckConcurrency: parsePositiveInt(firstEnv("WEBSITE_SECURITY_CHECK_CONCURRENCY", "SECFLOW_WEBSITE_SECURITY_CHECK_CONCURRENCY"), defaultWebsiteSecurityCheckConcurrency),
	}
}

func (c runtimeConfig) ListenAddr() string {
	return ":" + normalizeListenPort(c.HTTPPort)
}

func (c runtimeConfig) BaseURL() string {
	return "http://localhost:" + normalizeListenPort(c.HTTPPort)
}

func (c runtimeConfig) IsHostAgentMode() bool {
	return c.Role == "host-agent"
}

func (c runtimeConfig) ShouldProxyHostAgent() bool {
	return !c.IsHostAgentMode() && strings.TrimSpace(c.HostAgentURL) != ""
}

func (c runtimeConfig) PacketAnalyzerScriptArg() string {
	return firstNonEmpty(c.PacketAnalyzerScript, defaultPacketAnalyzerScript)
}

func (c runtimeConfig) BehaviorAnalyzerScriptArg() string {
	return firstNonEmpty(c.BehaviorAnalyzerScript, defaultBehaviorAnalyzerScript)
}

func (c runtimeConfig) LANMonitorScriptArg() string {
	return firstNonEmpty(c.LANMonitorScript, defaultLANMonitorScript)
}

func (c runtimeConfig) NICMonitorScriptArg() string {
	return firstNonEmpty(c.NICMonitorScript, defaultNICMonitorScript)
}

func normalizeRole(raw string) string {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	switch trimmed {
	case "", "control-plane":
		return "control-plane"
	case "host-agent":
		return "host-agent"
	default:
		return trimmed
	}
}

func normalizeURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func normalizeListenPort(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultHTTPPort
	}
	return strings.TrimPrefix(trimmed, ":")
}

func resolveProjectRootOverride() string {
	if raw := strings.TrimSpace(firstEnv("SECFLOW_PROJECT_ROOT")); raw != "" {
		if filepath.IsAbs(raw) {
			return filepath.Clean(raw)
		}
		cwd, _ := os.Getwd()
		if strings.TrimSpace(cwd) == "" {
			return filepath.Clean(raw)
		}
		return filepath.Join(cwd, raw)
	}
	return discoverProjectRoot()
}

func discoverProjectRoot() string {
	cwd, _ := os.Getwd()
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)

	dir := exeDir
	lowerExeDir := strings.ToLower(exeDir)
	if strings.Contains(lowerExeDir, "go-build") || strings.Contains(lowerExeDir, `\appdata\local\temp`) {
		dir = cwd
	}
	if strings.TrimSpace(dir) == "" {
		dir = cwd
	}
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}
	return dir
}

func resolveRuntimePath(projectRoot, raw, defaultRelative string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return filepath.Join(projectRoot, filepath.Clean(defaultRelative))
	}
	if filepath.IsAbs(trimmed) {
		return filepath.Clean(trimmed)
	}
	return filepath.Join(projectRoot, filepath.Clean(trimmed))
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func parsePositiveInt(raw string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
