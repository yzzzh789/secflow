package app

import (
	"path/filepath"
	"testing"
)

func TestBuildThreatCaptureArgs(t *testing.T) {
	original := appConfig
	appConfig = runtimeConfig{PacketAnalyzerScript: "./scripts/fake_packet.py"}
	defer func() {
		appConfig = original
	}()

	args, err := buildThreatCaptureArgs(managedCaptureCommand{
		Interface: "eth0",
		Count:     "20",
		Port:      "443",
		Provider:  "openai",
		APIKey:    "secret",
		APIBase:   "https://example.com/v1",
		Model:     "gpt-test",
	})
	if err != nil {
		t.Fatalf("buildThreatCaptureArgs() error = %v", err)
	}

	want := []string{
		"./scripts/fake_packet.py",
		"capture",
		"-i", "eth0",
		"-c", "20",
		"-p", "443",
		"--provider", "openai",
		"--api-base", "https://example.com/v1",
		"--model", "gpt-test",
	}
	if len(args) != len(want) {
		t.Fatalf("len(args) = %d, want %d (%v)", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; full args = %v", i, args[i], want[i], args)
		}
	}
}

func TestBuildThreatCaptureArgsMissingRequiredFields(t *testing.T) {
	if _, err := buildThreatCaptureArgs(managedCaptureCommand{Interface: "eth0"}); err == nil {
		t.Fatal("buildThreatCaptureArgs() error = nil, want bad request")
	}
}

func TestBuildLANMonitorArgs(t *testing.T) {
	original := appConfig
	appConfig = runtimeConfig{LANMonitorScript: "./scripts/fake_lan.py"}
	defer func() {
		appConfig = original
	}()

	args, err := buildLANMonitorArgs(managedCaptureCommand{
		Interface:     "wlan0",
		NoThreatIntel: "true",
	})
	if err != nil {
		t.Fatalf("buildLANMonitorArgs() error = %v", err)
	}

	want := []string{"./scripts/fake_lan.py", "-i", "wlan0", "--no-threat-intel"}
	if len(args) != len(want) {
		t.Fatalf("len(args) = %d, want %d (%v)", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; full args = %v", i, args[i], want[i], args)
		}
	}
}

func TestNICNamesFromCommand(t *testing.T) {
	names := nicNamesFromCommand(nicMonitorCommand{
		Nics: []string{" Ethernet0 ", "", "Wi-Fi"},
	})

	want := []string{"Ethernet0", "Wi-Fi"}
	if len(names) != len(want) {
		t.Fatalf("len(names) = %d, want %d (%v)", len(names), len(want), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestBuildNICMonitorArgs(t *testing.T) {
	original := appConfig
	appConfig = runtimeConfig{
		ProjectRoot:      `D:\secflow`,
		NICMonitorScript: "./traffic_monitor/fake_nic.py",
		NICTrafficDBPath: filepath.Join(`D:\secflow`, "data", "nic.sqlite"),
	}
	defer func() {
		appConfig = original
	}()

	args, err := buildNICMonitorArgs(nicMonitorCommand{Nics: []string{"Ethernet0"}})
	if err != nil {
		t.Fatalf("buildNICMonitorArgs() error = %v", err)
	}

	want := []string{
		"./traffic_monitor/fake_nic.py",
		"--mode", "interactive",
		"--db", filepath.Join(`D:\secflow`, "data", "nic.sqlite"),
	}
	if len(args) != len(want) {
		t.Fatalf("len(args) = %d, want %d (%v)", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; full args = %v", i, args[i], want[i], args)
		}
	}
}

func TestBuildNICMonitorArgsMissingNics(t *testing.T) {
	if _, err := buildNICMonitorArgs(nicMonitorCommand{}); err == nil {
		t.Fatal("buildNICMonitorArgs() error = nil, want bad request")
	}
}

func TestManagedCaptureCommandStringMap(t *testing.T) {
	command := managedCaptureCommand{
		Action:        "start",
		Interface:     "eth0",
		Count:         "50",
		Provider:      "openai",
		APIKey:        "secret",
		NoThreatIntel: "true",
	}

	got := command.StringMap()
	want := map[string]string{
		"action":          "start",
		"interface":       "eth0",
		"count":           "50",
		"provider":        "openai",
		"no_threat_intel": "true",
	}

	if len(got) != len(want) {
		t.Fatalf("len(StringMap()) = %d, want %d (%v)", len(got), len(want), got)
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Fatalf("StringMap()[%q] = %q, want %q; full map = %v", key, got[key], wantValue, got)
		}
	}
}

func TestNICMonitorCommandAnyMap(t *testing.T) {
	command := nicMonitorCommand{
		Action:  "start",
		Nics:    []string{" Ethernet0 ", "", "Wi-Fi"},
		Seconds: 30,
		StartTS: 100,
		EndTS:   200,
	}

	got := command.AnyMap()

	if got["action"] != "start" {
		t.Fatalf("AnyMap()[%q] = %v, want %q", "action", got["action"], "start")
	}

	names, ok := got["nics"].([]string)
	if !ok {
		t.Fatalf("AnyMap()[%q] type = %T, want []string", "nics", got["nics"])
	}

	wantNames := []string{"Ethernet0", "Wi-Fi"}
	if len(names) != len(wantNames) {
		t.Fatalf("len(AnyMap()[%q]) = %d, want %d (%v)", "nics", len(names), len(wantNames), names)
	}
	for i := range wantNames {
		if names[i] != wantNames[i] {
			t.Fatalf("AnyMap()[%q][%d] = %q, want %q", "nics", i, names[i], wantNames[i])
		}
	}

	if got["seconds"] != 30 {
		t.Fatalf("AnyMap()[%q] = %v, want %d", "seconds", got["seconds"], 30)
	}
	if got["start_ts"] != int64(100) {
		t.Fatalf("AnyMap()[%q] = %v, want %d", "start_ts", got["start_ts"], 100)
	}
	if got["end_ts"] != int64(200) {
		t.Fatalf("AnyMap()[%q] = %v, want %d", "end_ts", got["end_ts"], 200)
	}
}
