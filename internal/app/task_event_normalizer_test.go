package app

import (
	"encoding/json"
	"testing"
)

type normalizedEventEnvelope struct {
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

func decodeNormalizedEvent(t *testing.T, line string) normalizedEventEnvelope {
	t.Helper()

	var event normalizedEventEnvelope
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatalf("json.Unmarshal() error = %v, line = %q", err, line)
	}
	return event
}

func TestNormalizeProcessLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		line          ProcessLine
		finishMessage string
		wantType      string
		wantLevel     string
		wantMessage   string
		assertPayload func(*testing.T, map[string]any)
	}{
		{
			name:          "finish message becomes task event",
			line:          ProcessLine{Stream: "system", Text: "---CAPTURE-FINISHED---"},
			finishMessage: "---CAPTURE-FINISHED---",
			wantType:      "task_finished",
			wantLevel:     "info",
			wantMessage:   "task finished",
		},
		{
			name:        "packet event threat uses warning level",
			line:        ProcessLine{Stream: "stdout", Text: `{"id":"pkt-1","analysis":{"is_threat":true,"threat_type":"sql_injection"}}`},
			wantType:    "packet_event",
			wantLevel:   "warning",
			wantMessage: "sql_injection",
			assertPayload: func(t *testing.T, payload map[string]any) {
				t.Helper()
				if got := payload["id"]; got != "pkt-1" {
					t.Fatalf("payload[id] = %v, want pkt-1", got)
				}
			},
		},
		{
			name:        "info object becomes status event",
			line:        ProcessLine{Stream: "stdout", Text: `{"info":"ready"}`},
			wantType:    "status",
			wantLevel:   "info",
			wantMessage: "ready",
		},
		{
			name:        "activity log becomes session batch",
			line:        ProcessLine{Stream: "stdout", Text: `{"type":"activity_log","data":[{"id":"sess-1"}]}`},
			wantType:    "session_batch",
			wantLevel:   "info",
			wantMessage: "behavior sessions updated",
			assertPayload: func(t *testing.T, payload map[string]any) {
				t.Helper()
				sessions, ok := payload["sessions"].([]any)
				if !ok || len(sessions) != 1 {
					t.Fatalf("payload[sessions] = %#v, want one session", payload["sessions"])
				}
			},
		},
		{
			name:        "nic telemetry uses metric type",
			line:        ProcessLine{Stream: "stdout", Text: `{"type":"realtime_data","data":{"rx":1}}`},
			wantType:    "nic_telemetry",
			wantLevel:   "info",
			wantMessage: "nic telemetry updated",
			assertPayload: func(t *testing.T, payload map[string]any) {
				t.Helper()
				if got := payload["metricType"]; got != "realtime_data" {
					t.Fatalf("payload[metricType] = %v, want realtime_data", got)
				}
			},
		},
		{
			name:        "stderr raw line stays error",
			line:        ProcessLine{Stream: "stderr", Text: "fatal error: boom"},
			wantType:    "stderr",
			wantLevel:   "error",
			wantMessage: "fatal error: boom",
			assertPayload: func(t *testing.T, payload map[string]any) {
				t.Helper()
				if got := payload["text"]; got != "fatal error: boom" {
					t.Fatalf("payload[text] = %v, want fatal error: boom", got)
				}
			},
		},
		{
			name:        "traceback line is classified",
			line:        ProcessLine{Stream: "stdout", Text: "Traceback (most recent call last):"},
			wantType:    "python_traceback",
			wantLevel:   "error",
			wantMessage: "Traceback (most recent call last):",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			event := decodeNormalizedEvent(t, normalizeProcessLine("lan_monitor", tt.finishMessage, tt.line))
			if event.Version != "v1" {
				t.Fatalf("event.Version = %q, want v1", event.Version)
			}
			if event.Source != "lan_monitor" {
				t.Fatalf("event.Source = %q, want lan_monitor", event.Source)
			}
			if event.Stream != tt.line.Stream {
				t.Fatalf("event.Stream = %q, want %q", event.Stream, tt.line.Stream)
			}
			if event.Type != tt.wantType {
				t.Fatalf("event.Type = %q, want %q", event.Type, tt.wantType)
			}
			if event.Level != tt.wantLevel {
				t.Fatalf("event.Level = %q, want %q", event.Level, tt.wantLevel)
			}
			if event.Message != tt.wantMessage {
				t.Fatalf("event.Message = %q, want %q", event.Message, tt.wantMessage)
			}
			if event.Timestamp <= 0 {
				t.Fatalf("event.Timestamp = %d, want > 0", event.Timestamp)
			}
			if tt.assertPayload != nil {
				tt.assertPayload(t, event.Payload)
			}
		})
	}
}
