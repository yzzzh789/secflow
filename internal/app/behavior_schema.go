package app

import "encoding/json"

type trafficEnvelope struct {
	Type    string            `json:"type"`
	Message string            `json:"message"`
	Data    []json.RawMessage `json:"data"`
}

type behaviorSessionRow struct {
	SessionID     string                `json:"session_id"`
	CapturedAt    string                `json:"captured_at"`
	StartTime     string                `json:"start_time"`
	Duration      string                `json:"duration"`
	MainService   string                `json:"main_service"`
	MainDomain    string                `json:"main_domain"`
	Domain        string                `json:"domain"`
	FullHost      string                `json:"full_host"`
	SrcIP         string                `json:"src_ip"`
	DstIP         string                `json:"dst_ip"`
	AppName       string                `json:"app_name"`
	Category      string                `json:"category"`
	BehaviorLabel string                `json:"behavior_label"`
	RiskScore     int                   `json:"risk_score"`
	RiskLevel     string                `json:"risk_level"`
	RequestCount  int                   `json:"request_count"`
	Bytes         int64                 `json:"bytes"`
	EvidenceLevel string                `json:"evidence_level"`
	BehaviorChain []any                 `json:"behavior_chain"`
	Requests      []any                 `json:"requests"`
	SearchEvents  []auditSearchEvent    `json:"search_events"`
	Violations    []auditViolationEvent `json:"violations"`
}
