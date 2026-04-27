package app

import (
	"encoding/json"
	"testing"
)

func TestBuildInterfacesPayloadFromStructuredJSON(t *testing.T) {
	payload, err := buildInterfacesPayload([]byte(`{"nics":[{"name":"Wi-Fi","rawName":"WLAN"},{"name":"Ethernet"}]}`))
	if err != nil {
		t.Fatalf("buildInterfacesPayload() error = %v", err)
	}

	var interfaces []Interface
	if err := json.Unmarshal(payload, &interfaces); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(interfaces) != 2 {
		t.Fatalf("len(interfaces) = %d, want 2", len(interfaces))
	}
	if interfaces[0].Name != "Wi-Fi" || interfaces[0].RawName != "WLAN" {
		t.Fatalf("first interface = %+v", interfaces[0])
	}
	if interfaces[1].Name != "Ethernet" || interfaces[1].RawName != "Ethernet" {
		t.Fatalf("second interface = %+v", interfaces[1])
	}
}

func TestBuildNICListResponseNormalizesAndSorts(t *testing.T) {
	output := []byte(`{
		"nics": [
			{"name":"WLAN","displayName":"Wi-Fi","bytes_sent":2,"bytes_recv":3,"isup":false},
			{"name":"eth0","displayName":"Ethernet","bytes_sent":20,"bytes_recv":30,"isup":true},
			{"rawName":"eth0","displayName":"Ethernet duplicate","bytes_sent":1,"bytes_recv":1,"isup":true},
			{"name":"loopback","bytes_sent":1,"bytes_recv":1,"isup":true}
		]
	}`)

	payload, err := buildNICListResponse(output)
	if err != nil {
		t.Fatalf("buildNICListResponse() error = %v", err)
	}

	var response struct {
		Success bool        `json:"success"`
		Nics    []nicMetric `json:"nics"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if !response.Success {
		t.Fatalf("response.Success = false, want true")
	}
	if len(response.Nics) != 3 {
		t.Fatalf("len(response.Nics) = %d, want 3", len(response.Nics))
	}

	if response.Nics[0].Name != "eth0" || response.Nics[0].DisplayName != "Ethernet" {
		t.Fatalf("response.Nics[0] = %+v, want eth0/Ethernet first", response.Nics[0])
	}
	if response.Nics[1].Name != "loopback" || response.Nics[1].RawName != "loopback" {
		t.Fatalf("response.Nics[1] = %+v, want normalized loopback second", response.Nics[1])
	}
	if response.Nics[2].Name != "WLAN" || response.Nics[2].DisplayName != "Wi-Fi" {
		t.Fatalf("response.Nics[2] = %+v, want WLAN/Wi-Fi third", response.Nics[2])
	}
}

func TestBuildNICListResponseReturnsErrorForScriptError(t *testing.T) {
	_, err := buildNICListResponse([]byte(`{"error":"permission denied"}`))
	if err == nil {
		t.Fatal("buildNICListResponse() error = nil, want non-nil")
	}
}
