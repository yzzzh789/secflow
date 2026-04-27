package app

import (
	"encoding/json"
	"net/http"
	"strings"
)

func handleWebsiteSecurityState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if websiteSecurityServiceInstance == nil {
		http.Error(w, "Website security service unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(websiteSecurityServiceInstance.Snapshot()); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func handleWebsiteSecurityWebsites(w http.ResponseWriter, r *http.Request) {
	if websiteSecurityServiceInstance == nil {
		http.Error(w, "Website security service unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodPost:
		var payload websiteSecurityCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		monitor, err := websiteSecurityServiceInstance.AddWebsite(payload.URL, payload.IntervalMinutes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(monitor)
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "Missing website id", http.StatusBadRequest)
			return
		}
		if err := websiteSecurityServiceInstance.RemoveWebsite(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleWebsiteSecurityCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if websiteSecurityServiceInstance == nil {
		http.Error(w, "Website security service unavailable", http.StatusServiceUnavailable)
		return
	}

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		websiteSecurityServiceInstance.RunCheckAll()
	} else if err := websiteSecurityServiceInstance.RunCheck(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func handleWebsiteSecurityClearThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if websiteSecurityServiceInstance == nil {
		http.Error(w, "Website security service unavailable", http.StatusServiceUnavailable)
		return
	}

	if err := websiteSecurityServiceInstance.ClearThreats(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
