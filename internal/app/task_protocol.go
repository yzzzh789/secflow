package app

import "strings"

type managedCaptureCommand struct {
	Action        string `json:"action"`
	Interface     string `json:"interface,omitempty"`
	Count         string `json:"count,omitempty"`
	Port          string `json:"port,omitempty"`
	Provider      string `json:"provider,omitempty"`
	APIKey        string `json:"apiKey,omitempty"`
	APIBase       string `json:"apiBase,omitempty"`
	Model         string `json:"model,omitempty"`
	NoThreatIntel string `json:"no_threat_intel,omitempty"`
	Limit         string `json:"limit,omitempty"`
}

func (c managedCaptureCommand) StringMap() map[string]string {
	command := make(map[string]string, 10)
	if c.Action != "" {
		command["action"] = c.Action
	}
	if c.Interface != "" {
		command["interface"] = c.Interface
	}
	if c.Count != "" {
		command["count"] = c.Count
	}
	if c.Port != "" {
		command["port"] = c.Port
	}
	if c.Provider != "" {
		command["provider"] = c.Provider
	}
	if c.APIBase != "" {
		command["apiBase"] = c.APIBase
	}
	if c.Model != "" {
		command["model"] = c.Model
	}
	if c.NoThreatIntel != "" {
		command["no_threat_intel"] = c.NoThreatIntel
	}
	if c.Limit != "" {
		command["limit"] = c.Limit
	}
	return command
}

func (c managedCaptureCommand) withoutSecrets() managedCaptureCommand {
	c.APIKey = ""
	return c
}

type nicMonitorCommand struct {
	Action  string   `json:"action"`
	Nics    []string `json:"nics,omitempty"`
	Seconds int      `json:"seconds,omitempty"`
	StartTS int64    `json:"start_ts,omitempty"`
	EndTS   int64    `json:"end_ts,omitempty"`
}

func (c nicMonitorCommand) clone() nicMonitorCommand {
	cloned := c
	if len(c.Nics) > 0 {
		cloned.Nics = append([]string(nil), c.Nics...)
	}
	return cloned
}

func (c nicMonitorCommand) NICNames() []string {
	names := make([]string, 0, len(c.Nics))
	for _, raw := range c.Nics {
		name := strings.TrimSpace(raw)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func (c nicMonitorCommand) normalized() nicMonitorCommand {
	normalized := c.clone()
	normalized.Nics = c.NICNames()
	return normalized
}

func (c nicMonitorCommand) AnyMap() map[string]any {
	command := make(map[string]any, 5)
	if c.Action != "" {
		command["action"] = c.Action
	}
	if names := c.NICNames(); len(names) > 0 {
		command["nics"] = names
	}
	if c.Seconds != 0 {
		command["seconds"] = c.Seconds
	}
	if c.StartTS != 0 {
		command["start_ts"] = c.StartTS
	}
	if c.EndTS != 0 {
		command["end_ts"] = c.EndTS
	}
	return command
}

type managedCaptureRuntimeInfo struct {
	Active      bool                  `json:"active"`
	StartedAt   string                `json:"startedAt"`
	LastCommand managedCaptureCommand `json:"lastCommand"`
	HistorySize int                   `json:"historySize"`
}

type managedInteractiveRuntimeInfo struct {
	Active      bool              `json:"active"`
	StartedAt   string            `json:"startedAt"`
	LastCommand nicMonitorCommand `json:"lastCommand"`
	HistorySize int               `json:"historySize"`
}

type managedTaskRuntimeFields struct {
	DesiredState        string `json:"desiredState,omitempty"`
	RuntimeStatus       string `json:"runtimeStatus,omitempty"`
	AutoRestart         bool   `json:"autoRestart"`
	LastExitAt          string `json:"lastExitAt,omitempty"`
	LastExitReason      string `json:"lastExitReason,omitempty"`
	RestartCount        int    `json:"restartCount"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	NextRestartAt       string `json:"nextRestartAt,omitempty"`
	LastError           string `json:"lastError,omitempty"`
}

type managedCaptureRuntimePayload struct {
	managedCaptureRuntimeInfo
	managedTaskRuntimeFields
}

type managedInteractiveRuntimePayload struct {
	managedInteractiveRuntimeInfo
	managedTaskRuntimeFields
}

type dbPathResponse struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
}

type normalizedTaskEvent struct {
	Version   string         `json:"version"`
	Source    string         `json:"source"`
	Stream    string         `json:"stream"`
	Type      string         `json:"type"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Timestamp int64          `json:"timestamp"`
	Payload   map[string]any `json:"payload"`
	Raw       string         `json:"raw"`
}
