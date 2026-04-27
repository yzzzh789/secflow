package app

import (
	"database/sql"
	"encoding/json"
	"strings"
)

type persistedBehaviorSnapshot struct {
	RequestCount int
	Bytes        int64
}

func searchAuditEventExists(
	tx *sql.Tx,
	capturedAt, srcIP, engine, keyword string,
) (bool, error) {
	var exists int
	err := tx.QueryRow(
		`SELECT 1
		FROM search_audit_logs
		WHERE captured_at = ?
			AND COALESCE(src_ip, '') = ?
			AND COALESCE(engine, '') = ?
			AND COALESCE(keyword, '') = ?
		LIMIT 1`,
		capturedAt,
		srcIP,
		engine,
		keyword,
	).Scan(&exists)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func violationEventExists(
	tx *sql.Tx,
	capturedAt, srcIP, violationType, reason string,
) (bool, error) {
	var exists int
	err := tx.QueryRow(
		`SELECT 1
		FROM violation_events
		WHERE captured_at = ?
			AND COALESCE(src_ip, '') = ?
			AND COALESCE(violation_type, '') = ?
			AND COALESCE(reason, '') = ?
		LIMIT 1`,
		capturedAt,
		srcIP,
		violationType,
		reason,
	).Scan(&exists)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func loadPersistedBehaviorSnapshot(tx *sql.Tx, sessionID string) (persistedBehaviorSnapshot, error) {
	var snapshot persistedBehaviorSnapshot
	var rawJSON string
	err := tx.QueryRow(
		`SELECT request_count, raw_json FROM behavior_sessions WHERE session_id = ?`,
		sessionID,
	).Scan(&snapshot.RequestCount, &rawJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return persistedBehaviorSnapshot{}, nil
		}
		return persistedBehaviorSnapshot{}, err
	}

	if strings.TrimSpace(rawJSON) == "" {
		return snapshot, nil
	}

	var row behaviorSessionRow
	if err := json.Unmarshal([]byte(rawJSON), &row); err != nil {
		return snapshot, nil
	}
	snapshot.Bytes = row.Bytes
	return snapshot, nil
}

func ingestTrafficEnvelope(tx *sql.Tx, source, raw string) error {
	var env trafficEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		_, execErr := tx.Exec(
			`INSERT INTO ingest_logs (source, level, message, raw_text) VALUES (?, ?, ?, ?)`,
			source, "json_parse_error", err.Error(), raw,
		)
		return execErr
	}

	if env.Type != "activity_log" {
		_, err := tx.Exec(
			`INSERT INTO ingest_logs (source, level, message, raw_text) VALUES (?, ?, ?, ?)`,
			source, env.Type, env.Message, raw,
		)
		return err
	}

	for _, sessionRaw := range env.Data {
		var row behaviorSessionRow
		if err := json.Unmarshal(sessionRaw, &row); err != nil {
			_, _ = tx.Exec(
				`INSERT INTO ingest_logs (source, level, message, raw_text) VALUES (?, ?, ?, ?)`,
				source, "session_parse_error", err.Error(), string(sessionRaw),
			)
			continue
		}

		previous, err := loadPersistedBehaviorSnapshot(tx, row.SessionID)
		if err != nil {
			return err
		}

		behaviorChainJSON, _ := json.Marshal(row.BehaviorChain)
		requestsJSON, _ := json.Marshal(row.Requests)

		_, err = tx.Exec(
			`INSERT INTO behavior_sessions (
				session_id, last_seen, start_time, duration, main_service, main_domain,
				behavior_label, risk_score, risk_level, request_count,
				behavior_chain_json, requests_json, raw_json
			) VALUES (
				?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
			)
			ON CONFLICT(session_id) DO UPDATE SET
				last_seen=excluded.last_seen,
				start_time=excluded.start_time,
				duration=excluded.duration,
				main_service=excluded.main_service,
				main_domain=excluded.main_domain,
				behavior_label=excluded.behavior_label,
				risk_score=excluded.risk_score,
				risk_level=excluded.risk_level,
				request_count=excluded.request_count,
				behavior_chain_json=excluded.behavior_chain_json,
				requests_json=excluded.requests_json,
				raw_json=excluded.raw_json`,
			row.SessionID, row.StartTime, row.Duration, row.MainService, row.MainDomain,
			row.BehaviorLabel, row.RiskScore, row.RiskLevel, row.RequestCount,
			string(behaviorChainJSON), string(requestsJSON), string(sessionRaw),
		)
		if err != nil {
			return err
		}

		capturedAt := normalizeAuditTimestamp(row.CapturedAt)
		domain := strings.TrimSpace(row.Domain)
		if domain == "" {
			domain = strings.TrimSpace(row.MainDomain)
		}
		fullHost := strings.TrimSpace(row.FullHost)
		if fullHost == "" {
			fullHost = domain
		}

		deltaRequestCount := row.RequestCount
		if previous.RequestCount > 0 {
			deltaRequestCount = row.RequestCount - previous.RequestCount
		}
		if deltaRequestCount < 0 {
			deltaRequestCount = row.RequestCount
		}

		deltaBytes := row.Bytes
		if previous.Bytes > 0 {
			deltaBytes = row.Bytes - previous.Bytes
		}
		if deltaBytes < 0 {
			deltaBytes = row.Bytes
		}

		if domain != "" {
			if deltaRequestCount > 0 || deltaBytes > 0 {
				if _, err := tx.Exec(
					`INSERT INTO web_access_logs (
					captured_at, src_ip, dst_ip, domain, full_host, category, app_name,
					bytes, request_count, evidence_level, raw_json
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					capturedAt,
					strings.TrimSpace(row.SrcIP),
					strings.TrimSpace(row.DstIP),
					domain,
					fullHost,
					strings.TrimSpace(row.Category),
					strings.TrimSpace(row.AppName),
					deltaBytes,
					deltaRequestCount,
					strings.TrimSpace(row.EvidenceLevel),
					string(sessionRaw),
				); err != nil {
					return err
				}
			}
		}

		for _, event := range row.SearchEvents {
			eventCapturedAt := normalizeAuditTimestamp(event.CapturedAt)
			eventDomain := strings.TrimSpace(event.Domain)
			if eventDomain == "" {
				eventDomain = domain
			}
			eventSrcIP := strings.TrimSpace(event.SrcIP)
			if eventSrcIP == "" {
				eventSrcIP = strings.TrimSpace(row.SrcIP)
			}
			eventEvidence := strings.TrimSpace(event.EvidenceLevel)
			if eventEvidence == "" {
				eventEvidence = strings.TrimSpace(row.EvidenceLevel)
			}
			eventEngine := strings.TrimSpace(event.Engine)
			eventKeyword := strings.TrimSpace(event.Keyword)
			exists, err := searchAuditEventExists(tx, eventCapturedAt, eventSrcIP, eventEngine, eventKeyword)
			if err != nil {
				return err
			}
			if exists {
				continue
			}
			rawJSON := marshalAuditRawJSON(event, event.RawJSON)

			if _, err := tx.Exec(
				`INSERT INTO search_audit_logs (
					captured_at, src_ip, domain, engine, keyword, evidence_level, raw_json
				) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				eventCapturedAt,
				eventSrcIP,
				eventDomain,
				eventEngine,
				eventKeyword,
				eventEvidence,
				rawJSON,
			); err != nil {
				return err
			}
		}

		for _, event := range row.Violations {
			eventCapturedAt := normalizeAuditTimestamp(event.CapturedAt)
			eventDomain := strings.TrimSpace(event.Domain)
			if eventDomain == "" {
				eventDomain = domain
			}
			eventSrcIP := strings.TrimSpace(event.SrcIP)
			if eventSrcIP == "" {
				eventSrcIP = strings.TrimSpace(row.SrcIP)
			}
			eventType := strings.TrimSpace(event.ViolationType)
			eventReason := strings.TrimSpace(event.Reason)
			exists, err := violationEventExists(tx, eventCapturedAt, eventSrcIP, eventType, eventReason)
			if err != nil {
				return err
			}
			if exists {
				continue
			}
			rawJSON := marshalAuditRawJSON(event, event.RawJSON)

			if _, err := tx.Exec(
				`INSERT INTO violation_events (
					captured_at, src_ip, domain, violation_type, severity, reason, raw_json
				) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				eventCapturedAt,
				eventSrcIP,
				eventDomain,
				eventType,
				strings.TrimSpace(event.Severity),
				eventReason,
				rawJSON,
			); err != nil {
				return err
			}
		}
	}

	return nil
}
