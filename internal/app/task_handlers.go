package app

import (
	"net/http"
)

func handleManagedCaptureTaskControl(
	w http.ResponseWriter,
	r *http.Request,
	taskName string,
	hub *ManagedCaptureHub,
	buildArgs func(managedCaptureCommand) ([]string, error),
) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var command managedCaptureCommand
	if !decodeJSONBody(w, r, &command) {
		return
	}

	switch command.Action {
	case "start":
		args, err := buildArgs(command)
		if err != nil {
			writeHTTPError(w, err, http.StatusInternalServerError)
			return
		}
		if err := hub.Start(command, args...); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "stop":
		hub.Stop()
	default:
		http.Error(w, "Unsupported action", http.StatusBadRequest)
		return
	}

	handleManagedCaptureRuntime(w, taskName, hub.RuntimeInfo())
}

func handleThreatTaskControl(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	handleManagedCaptureTaskControl(w, r, taskKeyThreat, threatCaptureHub, buildThreatCaptureArgs)
}

func handleLANTaskControl(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	handleManagedCaptureTaskControl(w, r, taskKeyLAN, lanMonitorHub, buildLANMonitorArgs)
}

func handleNICTaskControl(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var command nicMonitorCommand
	if !decodeJSONBody(w, r, &command) {
		return
	}

	switch command.Action {
	case "start":
		args, err := buildNICMonitorArgs(command)
		if err != nil {
			writeHTTPError(w, err, http.StatusInternalServerError)
			return
		}
		if err := nicMonitorHub.Start(command, args...); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "stop":
		nicMonitorHub.Stop()
	default:
		http.Error(w, "Unsupported action", http.StatusBadRequest)
		return
	}

	handleManagedInteractiveRuntime(w, taskKeyNIC, nicMonitorHub.RuntimeInfo())
}
