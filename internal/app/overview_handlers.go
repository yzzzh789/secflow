package app

import (
	"net/http"
	"time"
)

func handleProductOverview(w http.ResponseWriter, r *http.Request) {
	if dbWriter == nil || dbWriter.db == nil {
		http.Error(w, errServiceUnavailable, http.StatusServiceUnavailable)
		return
	}

	packetDB := dbWriter.db
	if payload, ok := productOverviewCache.load(time.Now()); ok {
		writeJSONBytes(w, http.StatusOK, payload)
		return
	}

	payload, err := buildProductOverviewPayload(packetDB)
	if err != nil {
		http.Error(w, errJSONEncodeResponse, http.StatusInternalServerError)
		return
	}
	writeJSONBytes(w, http.StatusOK, productOverviewCache.store(payload, productOverviewCacheTTL))
}
