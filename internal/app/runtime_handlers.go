package app

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

func handleManagedCaptureRuntime(w http.ResponseWriter, taskName string, runtime managedCaptureRuntimeInfo) {
	respondJSON(w, buildManagedCaptureRuntimePayload(taskName, runtime))
}

func handleManagedInteractiveRuntime(w http.ResponseWriter, taskName string, runtime managedInteractiveRuntimeInfo) {
	respondJSON(w, buildManagedInteractiveRuntimePayload(taskName, runtime))
}

func handleGetDBPath(w http.ResponseWriter, r *http.Request) {
	exists := false
	if strings.TrimSpace(databasePath) != "" {
		_, err := os.Stat(databasePath)
		exists = err == nil
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(dbPathResponse{Path: databasePath, Exists: exists}); err != nil {
		http.Error(w, errJSONEncodeResponse, http.StatusInternalServerError)
	}
}

func handleThreatRuntime(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	handleManagedCaptureRuntime(w, taskKeyThreat, threatCaptureHub.RuntimeInfo())
}

func handleLANRuntime(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	handleManagedCaptureRuntime(w, taskKeyLAN, lanMonitorHub.RuntimeInfo())
}

func handleNICMonitorRuntime(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	handleManagedInteractiveRuntime(w, taskKeyNIC, nicMonitorHub.RuntimeInfo())
}

func handleTestAI(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var config struct {
		Provider string `json:"provider"`
		ApiKey   string `json:"apiKey"`
		ApiBase  string `json:"apiBase"`
		Model    string `json:"model"`
	}

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	args := []string{appConfig.PacketAnalyzerScriptArg(), "test-connection"}
	if config.Provider != "" {
		args = append(args, "--provider", config.Provider)
	}
	if config.ApiBase != "" {
		args = append(args, "--api-base", config.ApiBase)
	}
	if config.Model != "" {
		args = append(args, "--model", config.Model)
	}

	log.Printf("Testing AI connection: %v", redactedArgs(args))
	cmd := newPythonCommandWithEnv(args, apiKeyEnv(config.ApiKey)...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error testing AI connection: %s\nOutput: %s", err, string(output))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":false,"message":"Failed to execute test script"}`))
		return
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	lastLine := lines[len(lines)-1]

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(lastLine))
}
