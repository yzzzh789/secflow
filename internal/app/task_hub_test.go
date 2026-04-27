package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installFailingPythonCommandFactory(t *testing.T) {
	t.Helper()

	previousFactory := makePythonCommand
	missingPython := filepath.Join(t.TempDir(), "missing-python.exe")
	makePythonCommand = func(args ...string) *exec.Cmd {
		return exec.Command(missingPython, args...)
	}
	t.Cleanup(func() {
		makePythonCommand = previousFactory
	})
}

func installHelperPythonCommandFactory(t *testing.T) {
	t.Helper()

	previousFactory := makePythonCommand
	makePythonCommand = func(args ...string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=TestManagedHubHelperProcess", "--")
		cmd.Env = append(os.Environ(), "SECFLOW_TEST_HELPER_PROCESS=1")
		return cmd
	}
	t.Cleanup(func() {
		makePythonCommand = previousFactory
	})
}

func TestManagedHubHelperProcess(t *testing.T) {
	if os.Getenv("SECFLOW_TEST_HELPER_PROCESS") != "1" {
		return
	}
	fmt.Println(`{"type":"status","message":"ready"}`)
	time.Sleep(5 * time.Second)
	os.Exit(0)
}

func installTaskSupervisor(t *testing.T) (*TaskStateStore, func(string)) {
	t.Helper()

	previousSupervisor := taskSupervisor
	db, err := openDatabase(filepath.Join(t.TempDir(), "secflow.sqlite"))
	if err != nil {
		t.Fatalf("openDatabase() error = %v", err)
	}
	store := NewTaskStateStore(db)
	taskSupervisor = NewTaskSupervisor(store)

	t.Cleanup(func() {
		taskSupervisor = previousSupervisor
		_ = db.Close()
	})

	return store, func(taskName string) {
		taskSupervisor.cancelRestart(taskName)
	}
}

func TestManagedCaptureHubStartFailureUpdatesSupervisorState(t *testing.T) {
	installFailingPythonCommandFactory(t)
	store, cancelRestart := installTaskSupervisor(t)

	const taskName = "test-capture-start-failure"
	hub := NewManagedCaptureHub(taskName, "test_source", "", 10, true)
	command := managedCaptureCommand{Action: "start", Interface: "eth0", Count: "1"}

	err := hub.Start(command, "fake_script.py")
	if err == nil {
		t.Fatalf("Start() error = nil, want error")
	}
	cancelRestart(taskName)

	state, found, err := store.Get(taskName)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if !found {
		t.Fatalf("store.Get() found = false, want true")
	}
	if state.DesiredState != taskDesiredRunning {
		t.Fatalf("DesiredState = %q, want %q", state.DesiredState, taskDesiredRunning)
	}
	if state.RuntimeStatus != taskStatusBackoff {
		t.Fatalf("RuntimeStatus = %q, want %q", state.RuntimeStatus, taskStatusBackoff)
	}
	if state.LastError == "" {
		t.Fatalf("LastError is empty, want start failure reason")
	}
	if state.ConsecutiveFailures != 1 {
		t.Fatalf("ConsecutiveFailures = %d, want 1", state.ConsecutiveFailures)
	}
}

func TestManagedInteractiveHubStartFailureUpdatesSupervisorState(t *testing.T) {
	installFailingPythonCommandFactory(t)
	store, cancelRestart := installTaskSupervisor(t)

	const taskName = "test-interactive-start-failure"
	hub := NewManagedInteractiveHub(taskName, "test_nic", 10, true)
	command := nicMonitorCommand{Action: "start", Nics: []string{"eth0"}}

	err := hub.Start(command, "fake_nic.py")
	if err == nil {
		t.Fatalf("Start() error = nil, want error")
	}
	cancelRestart(taskName)

	state, found, err := store.Get(taskName)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if !found {
		t.Fatalf("store.Get() found = false, want true")
	}
	if state.RuntimeStatus != taskStatusBackoff {
		t.Fatalf("RuntimeStatus = %q, want %q", state.RuntimeStatus, taskStatusBackoff)
	}
	if state.LastError == "" {
		t.Fatalf("LastError is empty, want start failure reason")
	}
}

func TestManagedCaptureHubStartSuccessPersistsRedactedRuntimeState(t *testing.T) {
	installHelperPythonCommandFactory(t)
	store, cancelRestart := installTaskSupervisor(t)

	const taskName = "test-capture-start-success"
	hub := NewManagedCaptureHub(taskName, "test_source", "", 10, true)
	command := managedCaptureCommand{
		Action:    "start",
		Interface: "eth0",
		Count:     "1",
		Provider:  "openai",
		APIKey:    "secret-key",
	}
	args := []string{"fake_script.py", "--api-key", "secret-key"}

	if err := hub.Start(command, args...); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer hub.Stop()
	defer cancelRestart(taskName)

	runtimeInfo := hub.RuntimeInfo()
	if !runtimeInfo.Active {
		t.Fatal("RuntimeInfo().Active = false, want true")
	}
	if runtimeInfo.LastCommand.APIKey != "" {
		t.Fatalf("RuntimeInfo().LastCommand.APIKey = %q, want empty", runtimeInfo.LastCommand.APIKey)
	}

	state, found, err := store.Get(taskName)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if !found {
		t.Fatal("store.Get() found = false, want true")
	}
	if state.RuntimeStatus != taskStatusRunning {
		t.Fatalf("RuntimeStatus = %q, want %q", state.RuntimeStatus, taskStatusRunning)
	}
	if strings.Contains(state.CommandJSON, "secret-key") {
		t.Fatalf("CommandJSON contains secret: %s", state.CommandJSON)
	}
	if strings.Contains(state.ArgsJSON, "secret-key") {
		t.Fatalf("ArgsJSON contains secret: %s", state.ArgsJSON)
	}
	if !strings.Contains(state.ArgsJSON, "***") {
		t.Fatalf("ArgsJSON = %s, want redacted marker", state.ArgsJSON)
	}
}
