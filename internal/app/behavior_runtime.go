package app

import (
	"net/http"
	"strings"
)

var behaviorAnalysisHub = NewManagedCaptureHub(taskKeyBehavior, "behavior_analysis", "", 240, true)

func buildBehaviorAnalysisArgs(command managedCaptureCommand) ([]string, error) {
	iface := strings.TrimSpace(command.Interface)
	if iface == "" {
		return nil, newBadRequestError("Missing interface")
	}

	args := []string{appConfig.BehaviorAnalyzerScriptArg(), "-i", iface}
	if model := strings.TrimSpace(command.Model); model != "" {
		args = append(args, "--model", model)
	}
	if provider := strings.TrimSpace(command.Provider); provider != "" {
		args = append(args, "--provider", provider)
	}
	if apiBase := strings.TrimSpace(command.APIBase); apiBase != "" {
		args = append(args, "--api-base", apiBase)
	}
	if limit := strings.TrimSpace(command.Limit); limit != "" {
		args = append(args, "--limit", limit)
	}
	return args, nil
}

func handleTrafficAnalysis(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}

	handleManagedCaptureWebSocket(
		w,
		r,
		"Traffic Analysis WebSocket connected",
		behaviorAnalysisHub,
		buildBehaviorAnalysisArgs,
		"Starting Traffic Analyzer",
		"Error starting analyzer",
	)
}

func handleBehaviorRuntime(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	handleManagedCaptureRuntime(w, taskKeyBehavior, behaviorAnalysisHub.RuntimeInfo())
}

func handleBehaviorTaskControl(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	handleManagedCaptureTaskControl(w, r, taskKeyBehavior, behaviorAnalysisHub, buildBehaviorAnalysisArgs)
}
