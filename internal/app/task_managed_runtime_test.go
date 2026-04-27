package app

import (
	"path/filepath"
	"testing"
)

func TestDecodeManagedCaptureCommand(t *testing.T) {
	t.Parallel()

	command, err := decodeManagedCaptureCommand(`{"action":"start","interface":"eth0","count":"20","provider":"openai"}`)
	if err != nil {
		t.Fatalf("decodeManagedCaptureCommand() error = %v", err)
	}

	if command.Action != "start" {
		t.Fatalf("Action = %q, want start", command.Action)
	}
	if command.Interface != "eth0" {
		t.Fatalf("Interface = %q, want eth0", command.Interface)
	}
	if command.Count != "20" {
		t.Fatalf("Count = %q, want 20", command.Count)
	}
	if command.Provider != "openai" {
		t.Fatalf("Provider = %q, want openai", command.Provider)
	}
}

func TestBuildManagedCaptureRuntimePayloadIncludesSupervisorFields(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secflow.sqlite")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error = %v", err)
	}
	defer db.Close()

	store := NewTaskStateStore(db)
	command := managedCaptureCommand{Action: "start", Interface: "eth0", Count: "20"}
	args := []string{"./scripts/fake_packet.py", "capture", "-i", "eth0", "-c", "20"}
	if err := store.MarkRunning(taskKeyThreat, command, args, true); err != nil {
		t.Fatalf("MarkRunning() error = %v", err)
	}

	original := taskSupervisor
	taskSupervisor = NewTaskSupervisor(store)
	defer func() {
		taskSupervisor = original
	}()

	payload := buildManagedCaptureRuntimePayload(taskKeyThreat, managedCaptureRuntimeInfo{
		Active:      true,
		StartedAt:   "2026-04-26T16:00:00Z",
		LastCommand: command,
		HistorySize: 3,
	})

	if !payload.Active {
		t.Fatal("payload.Active = false, want true")
	}
	if payload.LastCommand.Interface != "eth0" {
		t.Fatalf("payload.LastCommand.Interface = %q, want eth0", payload.LastCommand.Interface)
	}
	if payload.RuntimeStatus != taskStatusRunning {
		t.Fatalf("payload.RuntimeStatus = %q, want %q", payload.RuntimeStatus, taskStatusRunning)
	}
	if payload.DesiredState != taskDesiredRunning {
		t.Fatalf("payload.DesiredState = %q, want %q", payload.DesiredState, taskDesiredRunning)
	}
	if !payload.AutoRestart {
		t.Fatal("payload.AutoRestart = false, want true")
	}
}

func TestBuildManagedInteractiveRuntimePayloadIncludesSupervisorFields(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secflow.sqlite")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error = %v", err)
	}
	defer db.Close()

	store := NewTaskStateStore(db)
	command := nicMonitorCommand{Action: "start", Nics: []string{" Ethernet0 ", "Wi-Fi"}}
	args := []string{"./traffic_monitor/fake_nic.py", "--mode", "interactive"}
	if err := store.MarkRunning(taskKeyNIC, command.normalized(), args, true); err != nil {
		t.Fatalf("MarkRunning() error = %v", err)
	}

	original := taskSupervisor
	taskSupervisor = NewTaskSupervisor(store)
	defer func() {
		taskSupervisor = original
	}()

	payload := buildManagedInteractiveRuntimePayload(taskKeyNIC, managedInteractiveRuntimeInfo{
		Active:      true,
		StartedAt:   "2026-04-26T16:00:00Z",
		LastCommand: command.normalized(),
		HistorySize: 5,
	})

	names := payload.LastCommand.NICNames()
	if len(names) != 2 || names[0] != "Ethernet0" || names[1] != "Wi-Fi" {
		t.Fatalf("payload.LastCommand.NICNames() = %v, want [Ethernet0 Wi-Fi]", names)
	}
	if payload.RuntimeStatus != taskStatusRunning {
		t.Fatalf("payload.RuntimeStatus = %q, want %q", payload.RuntimeStatus, taskStatusRunning)
	}
	if payload.DesiredState != taskDesiredRunning {
		t.Fatalf("payload.DesiredState = %q, want %q", payload.DesiredState, taskDesiredRunning)
	}
	if !payload.AutoRestart {
		t.Fatal("payload.AutoRestart = false, want true")
	}
}
