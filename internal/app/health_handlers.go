package app

import (
	"net/http"
	"os"
	"time"
)

type healthComponent struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Path    string `json:"path,omitempty"`
}

type healthResponse struct {
	Status     string                     `json:"status"`
	Timestamp  string                     `json:"timestamp"`
	ListenAddr string                     `json:"listenAddr,omitempty"`
	Components map[string]healthComponent `json:"components"`
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:     "ok",
		Timestamp:  time.Now().Format(time.RFC3339),
		ListenAddr: appConfig.ListenAddr(),
		Components: map[string]healthComponent{
			"http": {Status: "ok", Message: "http ready"},
		},
	})
}

func handleReadyz(w http.ResponseWriter, r *http.Request) {
	components := map[string]healthComponent{
		"packet_db":              packetDBHealth(),
		"task_state_store":       taskStateStoreHealth(),
		"task_supervisor":        taskSupervisorHealth(),
		"website_security_state": websiteSecurityHealth(),
		"nic_db":                 nicDBHealth(),
	}
	if appConfig.ShouldProxyHostAgent() {
		components["host_agent"] = hostAgentHealth()
	}

	statusCode := http.StatusOK
	status := aggregateHealthStatus(components)
	if status == "fail" {
		statusCode = http.StatusServiceUnavailable
	}

	writeJSON(w, statusCode, healthResponse{
		Status:     status,
		Timestamp:  time.Now().Format(time.RFC3339),
		ListenAddr: appConfig.ListenAddr(),
		Components: components,
	})
}

func handleRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, appConfig)
}

func packetDBHealth() healthComponent {
	path := resolveDatabasePath()
	if dbWriter == nil || dbWriter.db == nil {
		return healthComponent{Status: "fail", Message: "packet database not initialized", Path: path}
	}
	if err := dbWriter.db.Ping(); err != nil {
		return healthComponent{Status: "fail", Message: err.Error(), Path: path}
	}
	return healthComponent{Status: "ok", Message: "packet database ready", Path: path}
}

func taskStateStoreHealth() healthComponent {
	if taskStateStore == nil {
		return healthComponent{Status: "fail", Message: "task state store not initialized"}
	}
	return healthComponent{Status: "ok", Message: "task state available"}
}

func taskSupervisorHealth() healthComponent {
	if taskSupervisor == nil {
		return healthComponent{Status: "fail", Message: "task supervisor not initialized"}
	}
	return healthComponent{Status: "ok", Message: "task supervisor ready"}
}

func websiteSecurityHealth() healthComponent {
	path := resolveWebsiteSecurityStatePath()
	if websiteSecurityServiceInstance == nil {
		return healthComponent{Status: "fail", Message: "website security service not initialized", Path: path}
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return healthComponent{Status: "degraded", Message: "state file not created yet", Path: path}
		}
		return healthComponent{Status: "fail", Message: err.Error(), Path: path}
	}
	return healthComponent{Status: "ok", Message: "website security state available", Path: path}
}

func nicDBHealth() healthComponent {
	path := resolveNICDatabasePath()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return healthComponent{Status: "degraded", Message: "nic database not created yet", Path: path}
		}
		return healthComponent{Status: "fail", Message: err.Error(), Path: path}
	}
	return healthComponent{Status: "ok", Message: "nic database available", Path: path}
}

func aggregateHealthStatus(components map[string]healthComponent) string {
	overall := "ok"
	for _, component := range components {
		switch component.Status {
		case "fail":
			return "fail"
		case "degraded":
			overall = "degraded"
		}
	}
	return overall
}
