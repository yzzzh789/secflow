package app

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
)

func mustIngestBehaviorEnvelope(t *testing.T, db *sql.DB, row behaviorSessionRow) {
	t.Helper()

	payload, err := json.Marshal(trafficEnvelope{
		Type: "activity_log",
		Data: []json.RawMessage{mustMarshalJSON(t, row)},
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}

	if err := ingestTrafficEnvelope(tx, "test", string(payload)); err != nil {
		_ = tx.Rollback()
		t.Fatalf("ingest envelope: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
}

func mustMarshalJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return data
}

func TestIngestTrafficEnvelopeStoresWebAccessLogDeltas(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "behavior-ingest.sqlite")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	base := behaviorSessionRow{
		SessionID:     "sess_behavior_delta",
		CapturedAt:    "2026-04-25 20:00:00",
		StartTime:     "20:00",
		Duration:      "10s",
		MainService:   "github",
		MainDomain:    "github.com",
		Domain:        "github.com",
		FullHost:      "github.com",
		SrcIP:         "192.0.2.10",
		DstIP:         "198.51.100.10",
		AppName:       "GitHub",
		Category:      "work",
		BehaviorLabel: "Visited github",
		RiskLevel:     "low",
		EvidenceLevel: "medium",
	}

	first := base
	first.RequestCount = 3
	first.Bytes = 300
	mustIngestBehaviorEnvelope(t, db, first)

	second := base
	second.CapturedAt = "2026-04-25 20:00:05"
	second.Duration = "15s"
	second.RequestCount = 7
	second.Bytes = 700
	mustIngestBehaviorEnvelope(t, db, second)

	var totalRequests int
	var totalBytes int64
	if err := db.QueryRow(`SELECT COALESCE(SUM(request_count), 0), COALESCE(SUM(bytes), 0) FROM web_access_logs`).Scan(&totalRequests, &totalBytes); err != nil {
		t.Fatalf("query totals: %v", err)
	}

	if totalRequests != 7 {
		t.Fatalf("expected total request_count 7, got %d", totalRequests)
	}
	if totalBytes != 700 {
		t.Fatalf("expected total bytes 700, got %d", totalBytes)
	}

	var latestRequestCount int
	if err := db.QueryRow(`SELECT request_count FROM behavior_sessions WHERE session_id = ?`, base.SessionID).Scan(&latestRequestCount); err != nil {
		t.Fatalf("query behavior session: %v", err)
	}
	if latestRequestCount != 7 {
		t.Fatalf("expected persisted session request_count 7, got %d", latestRequestCount)
	}
}

func TestIngestTrafficEnvelopeDeduplicatesSearchAndViolationEvents(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "behavior-events.sqlite")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	base := behaviorSessionRow{
		SessionID:     "sess_behavior_events",
		CapturedAt:    "2026-04-25 20:10:00",
		StartTime:     "20:10",
		Duration:      "5s",
		MainService:   "google",
		MainDomain:    "google.com",
		Domain:        "google.com",
		FullHost:      "www.google.com",
		SrcIP:         "192.0.2.11",
		DstIP:         "198.51.100.11",
		AppName:       "Google",
		Category:      "search",
		BehaviorLabel: "Search",
		RiskLevel:     "low",
		EvidenceLevel: "high",
		RequestCount:  1,
		Bytes:         120,
		SearchEvents: []auditSearchEvent{
			{
				CapturedAt:    "2026-04-25 20:10:00",
				SrcIP:         "192.0.2.11",
				Domain:        "google.com",
				Engine:        "google",
				Keyword:       "golang sqlite",
				EvidenceLevel: "high",
			},
		},
		Violations: []auditViolationEvent{
			{
				CapturedAt:    "2026-04-25 20:10:00",
				SrcIP:         "192.0.2.11",
				Domain:        "google.com",
				ViolationType: "high_risk_keyword",
				Severity:      "medium",
				Reason:        "matched keyword: sqlite",
			},
		},
	}

	mustIngestBehaviorEnvelope(t, db, base)
	mustIngestBehaviorEnvelope(t, db, base)

	var searchCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM search_audit_logs`).Scan(&searchCount); err != nil {
		t.Fatalf("query search count: %v", err)
	}
	if searchCount != 1 {
		t.Fatalf("expected 1 search audit log, got %d", searchCount)
	}

	var violationCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM violation_events`).Scan(&violationCount); err != nil {
		t.Fatalf("query violation count: %v", err)
	}
	if violationCount != 1 {
		t.Fatalf("expected 1 violation event, got %d", violationCount)
	}
}
