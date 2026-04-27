package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeListenPort(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "default", raw: "", want: defaultHTTPPort},
		{name: "plain", raw: "8081", want: "8081"},
		{name: "prefixed", raw: ":8082", want: "8082"},
		{name: "whitespace", raw: " 9090 ", want: "9090"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeListenPort(tc.raw); got != tc.want {
				t.Fatalf("normalizeListenPort(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestResolveRuntimePath(t *testing.T) {
	t.Parallel()

	root := filepath.Join("D:", "repo")
	defaultPath := filepath.Join("data", "packet_analyzer.sqlite")

	if got := resolveRuntimePath(root, "", defaultPath); got != filepath.Join(root, defaultPath) {
		t.Fatalf("default resolveRuntimePath() = %q", got)
	}

	if got := resolveRuntimePath(root, filepath.Join("custom", "db.sqlite"), defaultPath); got != filepath.Join(root, "custom", "db.sqlite") {
		t.Fatalf("relative resolveRuntimePath() = %q", got)
	}

	absolute := filepath.Join(string(os.PathSeparator), "runtime", "db.sqlite")
	want := filepath.Join(root, "runtime", "db.sqlite")
	if filepath.IsAbs(absolute) {
		want = absolute
	}
	if got := resolveRuntimePath(root, absolute, defaultPath); got != want {
		t.Fatalf("absolute resolveRuntimePath() = %q, want %q", got, want)
	}
}

func TestNormalizeRole(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want string
	}{
		{raw: "", want: "control-plane"},
		{raw: "control-plane", want: "control-plane"},
		{raw: "HOST-AGENT", want: "host-agent"},
		{raw: "custom", want: "custom"},
	}

	for _, tc := range cases {
		if got := normalizeRole(tc.raw); got != tc.want {
			t.Fatalf("normalizeRole(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	t.Parallel()

	if got := normalizeURL(" http://host.docker.internal:9091/ "); got != "http://host.docker.internal:9091" {
		t.Fatalf("normalizeURL() = %q", got)
	}
}

func TestRuntimeConfigScriptDefaults(t *testing.T) {
	t.Parallel()

	cfg := runtimeConfig{}
	if got := cfg.PacketAnalyzerScriptArg(); got != defaultPacketAnalyzerScript {
		t.Fatalf("PacketAnalyzerScriptArg() = %q, want %q", got, defaultPacketAnalyzerScript)
	}
	if got := cfg.BehaviorAnalyzerScriptArg(); got != defaultBehaviorAnalyzerScript {
		t.Fatalf("BehaviorAnalyzerScriptArg() = %q, want %q", got, defaultBehaviorAnalyzerScript)
	}
	if got := cfg.LANMonitorScriptArg(); got != defaultLANMonitorScript {
		t.Fatalf("LANMonitorScriptArg() = %q, want %q", got, defaultLANMonitorScript)
	}
	if got := cfg.NICMonitorScriptArg(); got != defaultNICMonitorScript {
		t.Fatalf("NICMonitorScriptArg() = %q, want %q", got, defaultNICMonitorScript)
	}
}

func TestLoadRuntimeConfigScriptEnvOverrides(t *testing.T) {
	t.Setenv("SECFLOW_PACKET_ANALYZER_SCRIPT", "custom/packet.py")
	t.Setenv("SECFLOW_BEHAVIOR_ANALYZER_SCRIPT", "custom/behavior.py")
	t.Setenv("SECFLOW_LAN_MONITOR_SCRIPT", "custom/lan.py")
	t.Setenv("SECFLOW_NIC_MONITOR_SCRIPT", "custom/nic.py")

	cfg := loadRuntimeConfig()

	if cfg.PacketAnalyzerScript != "custom/packet.py" {
		t.Fatalf("PacketAnalyzerScript = %q", cfg.PacketAnalyzerScript)
	}
	if cfg.BehaviorAnalyzerScript != "custom/behavior.py" {
		t.Fatalf("BehaviorAnalyzerScript = %q", cfg.BehaviorAnalyzerScript)
	}
	if cfg.LANMonitorScript != "custom/lan.py" {
		t.Fatalf("LANMonitorScript = %q", cfg.LANMonitorScript)
	}
	if cfg.NICMonitorScript != "custom/nic.py" {
		t.Fatalf("NICMonitorScript = %q", cfg.NICMonitorScript)
	}
}

func TestLoadRuntimeConfigControlToken(t *testing.T) {
	t.Setenv("SECFLOW_CONTROL_TOKEN", " secret-token ")

	cfg := loadRuntimeConfig()

	if cfg.ControlToken != "secret-token" {
		t.Fatalf("ControlToken = %q", cfg.ControlToken)
	}
}
