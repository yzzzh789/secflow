package app

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

var taskSupervisor *TaskSupervisor

var threatCaptureHub = NewManagedCaptureHub(taskKeyThreat, "threat_detection", "---CAPTURE-FINISHED---", 240, false)
var lanMonitorHub = NewManagedCaptureHub(taskKeyLAN, "lan_monitor", "", 240, true)
var nicMonitorHub = NewManagedInteractiveHub(taskKeyNIC, "nic_monitor", 400, true)

func decodeStringSlice(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var items []string
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, err
	}
	return items, nil
}

func decodeManagedCaptureCommand(raw string) (managedCaptureCommand, error) {
	if strings.TrimSpace(raw) == "" {
		return managedCaptureCommand{}, nil
	}
	var command managedCaptureCommand
	if err := json.Unmarshal([]byte(raw), &command); err != nil {
		return managedCaptureCommand{}, err
	}
	return command, nil
}

func decodeNICMonitorCommand(raw string) (nicMonitorCommand, error) {
	if strings.TrimSpace(raw) == "" {
		return nicMonitorCommand{}, nil
	}
	var command nicMonitorCommand
	if err := json.Unmarshal([]byte(raw), &command); err != nil {
		return nicMonitorCommand{}, err
	}
	return command, nil
}

func isManagedTaskActive(taskName string) bool {
	switch taskName {
	case taskKeyThreat:
		return threatCaptureHub.IsActive()
	case taskKeyBehavior:
		return behaviorAnalysisHub.IsActive()
	case taskKeyLAN:
		return lanMonitorHub.IsActive()
	case taskKeyNIC:
		return nicMonitorHub.IsActive()
	default:
		return false
	}
}

func startManagedTaskFromState(state managedTaskState) error {
	if !shouldManageTaskLocally(state.TaskName) {
		log.Printf("Skipping local restore for proxied task %s via host agent %s", state.TaskName, appConfig.HostAgentURL)
		return nil
	}

	args, err := decodeStringSlice(state.ArgsJSON)
	if err != nil {
		return fmt.Errorf("decode args: %w", err)
	}
	if len(args) == 0 {
		return fmt.Errorf("missing persisted args")
	}

	switch state.TaskName {
	case taskKeyThreat:
		command, err := decodeManagedCaptureCommand(state.CommandJSON)
		if err != nil {
			return fmt.Errorf("decode threat command: %w", err)
		}
		command.APIKey = taskAPIKey(state.TaskName)
		return threatCaptureHub.Start(command, args...)
	case taskKeyBehavior:
		command, err := decodeManagedCaptureCommand(state.CommandJSON)
		if err != nil {
			return fmt.Errorf("decode behavior command: %w", err)
		}
		command.APIKey = taskAPIKey(state.TaskName)
		return behaviorAnalysisHub.Start(command, args...)
	case taskKeyLAN:
		command, err := decodeManagedCaptureCommand(state.CommandJSON)
		if err != nil {
			return fmt.Errorf("decode lan command: %w", err)
		}
		return lanMonitorHub.Start(command, args...)
	case taskKeyNIC:
		command, err := decodeNICMonitorCommand(state.CommandJSON)
		if err != nil {
			return fmt.Errorf("decode nic command: %w", err)
		}
		return nicMonitorHub.Start(command, args...)
	default:
		return fmt.Errorf("unknown task %q", state.TaskName)
	}
}

func buildManagedCaptureRuntimePayload(taskName string, runtime managedCaptureRuntimeInfo) managedCaptureRuntimePayload {
	payload := managedCaptureRuntimePayload{managedCaptureRuntimeInfo: runtime}
	if taskSupervisor == nil {
		return payload
	}

	if fields, ok := taskSupervisor.RuntimeFields(taskName); ok {
		payload.managedTaskRuntimeFields = fields
	}
	return payload
}

func buildManagedInteractiveRuntimePayload(taskName string, runtime managedInteractiveRuntimeInfo) managedInteractiveRuntimePayload {
	payload := managedInteractiveRuntimePayload{managedInteractiveRuntimeInfo: runtime}
	if taskSupervisor == nil {
		return payload
	}

	if fields, ok := taskSupervisor.RuntimeFields(taskName); ok {
		payload.managedTaskRuntimeFields = fields
	}
	return payload
}
