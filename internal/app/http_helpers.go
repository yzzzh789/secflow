package app

import (
	"encoding/json"
	"net/http"
)

const (
	errJSONEncodeResponse = "failed to encode JSON response"
	errWriteResponse      = "failed to write response"
	errServiceUnavailable = "service unavailable"
)

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, errJSONEncodeResponse, http.StatusInternalServerError)
	}
}

func writeJSONBytes(w http.ResponseWriter, status int, payload []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(payload); err != nil {
		http.Error(w, errWriteResponse, http.StatusInternalServerError)
	}
}

type statusError struct {
	status  int
	message string
}

func (e statusError) Error() string {
	return e.message
}

func newBadRequestError(message string) error {
	return statusError{status: http.StatusBadRequest, message: message}
}

func writeHTTPError(w http.ResponseWriter, err error, fallbackStatus int) {
	if err == nil {
		return
	}
	if httpErr, ok := err.(statusError); ok {
		http.Error(w, httpErr.message, httpErr.status)
		return
	}
	http.Error(w, err.Error(), fallbackStatus)
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

func respondJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, errJSONEncodeResponse, http.StatusInternalServerError)
	}
}
