package app

import (
	"log"
	"net/http"
	"time"
)

func handleGetNICList(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}

	log.Println("Request received for /api/nic/list")
	if payload, ok := nicListCache.load(time.Now()); ok {
		writeJSONBytes(w, http.StatusOK, payload)
		return
	}

	cmd := newPythonCommand(nicDiscoveryArgs()...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error getting NIC list: %s\nOutput: %s", err, string(output))
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   "Failed to get NIC list",
		})
		return
	}

	payload, err := buildNICListResponse(output)
	if err != nil {
		log.Printf("Error parsing NIC list: %s\nOutput: %s", err, string(output))
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   "Failed to parse NIC list",
		})
		return
	}

	writeJSONBytes(w, http.StatusOK, nicListCache.store(payload, nicListCacheTTL))
}
