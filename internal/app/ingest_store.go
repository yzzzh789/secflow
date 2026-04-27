package app

import (
	"database/sql"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"
)

type IngestItem struct {
	Source string
	Line   string
}

type ProcessLine struct {
	Stream string
	Text   string
}

type DBWriter struct {
	db *sql.DB
	ch chan IngestItem

	wg   sync.WaitGroup
	quit chan struct{}
}

func NewDBWriter(db *sql.DB) *DBWriter {
	w := &DBWriter{
		db:   db,
		ch:   make(chan IngestItem, 5000),
		quit: make(chan struct{}),
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

func (w *DBWriter) Close() error {
	close(w.quit)
	w.wg.Wait()
	return w.db.Close()
}

func (w *DBWriter) Enqueue(source, line string) {
	item := IngestItem{Source: source, Line: line}
	select {
	case <-w.quit:
		return
	case w.ch <- item:
	}
}

func (w *DBWriter) loop() {
	defer w.wg.Done()

	ticker := time.NewTicker(800 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]IngestItem, 0, 200)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := w.flush(batch); err != nil {
			log.Printf("db flush error: %v", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-w.quit:
			for {
				select {
				case item := <-w.ch:
					batch = append(batch, item)
					if len(batch) >= 200 {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case item := <-w.ch:
			batch = append(batch, item)
			if len(batch) >= 200 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *DBWriter) flush(items []IngestItem) error {
	tx, err := w.db.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for _, item := range items {
		if err := ingestLine(tx, item.Source, item.Line); err != nil {
			log.Printf("db ingest error: %v (source=%s)", err, item.Source)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

type lanBehaviorReport struct {
	IP                 string `json:"ip"`
	FirstSeen          string `json:"first_seen"`
	LastSeen           string `json:"last_seen"`
	Duration           string `json:"duration"`
	TotalRequests      int    `json:"total_requests"`
	TotalBytesSent     string `json:"total_bytes_sent"`
	TotalBytesReceived string `json:"total_bytes_received"`
	UniqueDomains      int    `json:"unique_domains"`
	RiskScore          int    `json:"risk_score"`
	RiskLevel          string `json:"risk_level"`
	TopDomains         []any  `json:"top_domains"`
	CategoryStats      any    `json:"category_stats"`
	RiskEvents         []any  `json:"risk_events"`
}

func ingestLine(tx *sql.Tx, source, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if line == "---CAPTURE-FINISHED---" {
		_, err := tx.Exec(
			`INSERT INTO ingest_logs (source, level, message, raw_text) VALUES (?, ?, ?, ?)`,
			source, "status", "CAPTURE_FINISHED", line,
		)
		return err
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		_, execErr := tx.Exec(
			`INSERT INTO ingest_logs (source, level, message, raw_text) VALUES (?, ?, ?, ?)`,
			source, "raw", "", line,
		)
		return execErr
	}

	if _, ok := m["id"]; ok && m["analysis"] != nil {
		return ingestPacketEvent(tx, line, m)
	}

	if t, ok := m["type"]; ok && t != nil {
		var typeStr string
		_ = json.Unmarshal(t, &typeStr)
		if typeStr == "behavior_report" {
			return ingestLANBehaviorReport(tx, source, line)
		}
		return ingestTrafficEnvelope(tx, source, line)
	}

	for _, key := range []string{"error", "warning", "info"} {
		if v, ok := m[key]; ok && v != nil {
			var msg string
			_ = json.Unmarshal(v, &msg)
			_, err := tx.Exec(
				`INSERT INTO ingest_logs (source, level, message, raw_text) VALUES (?, ?, ?, ?)`,
				source, key, msg, line,
			)
			return err
		}
	}

	_, err := tx.Exec(
		`INSERT INTO ingest_logs (source, level, message, raw_text) VALUES (?, ?, ?, ?)`,
		source, "json", "", line,
	)
	return err
}

func ingestPacketEvent(tx *sql.Tx, raw string, m map[string]json.RawMessage) error {
	var captureID int
	_ = json.Unmarshal(m["id"], &captureID)

	var ts float64
	_ = json.Unmarshal(m["timestamp"], &ts)

	var src, dst, proto string
	_ = json.Unmarshal(m["src"], &src)
	_ = json.Unmarshal(m["dst"], &dst)
	_ = json.Unmarshal(m["proto"], &proto)

	var length int
	_ = json.Unmarshal(m["len"], &length)

	analysisJSON := ""
	if m["analysis"] != nil {
		analysisJSON = string(m["analysis"])
	}
	packetDetailsJSON := ""
	if m["packet_details"] != nil {
		packetDetailsJSON = string(m["packet_details"])
	}

	isThreat := 0
	threatType := ""
	reason := ""
	summary := ""
	firewallAction := ""

	var analysisMap map[string]any
	if m["analysis"] != nil && json.Unmarshal(m["analysis"], &analysisMap) == nil {
		switch v := analysisMap["is_threat"].(type) {
		case bool:
			if v {
				isThreat = 1
			}
		case string:
			if strings.EqualFold(v, "true") {
				isThreat = 1
			}
		}
		if v, ok := analysisMap["threat_type"].(string); ok {
			threatType = v
		}
		if v, ok := analysisMap["reason"].(string); ok {
			reason = v
		}
		if v, ok := analysisMap["summary"].(string); ok {
			summary = v
		}
		if v, ok := analysisMap["firewall_action"].(string); ok {
			firewallAction = v
		}
	}

	_, err := tx.Exec(
		`INSERT INTO packet_events (
			capture_id, event_timestamp, src_ip, dst_ip, proto, length,
			is_threat, threat_type, reason, summary, firewall_action,
			packet_details_json, analysis_json, raw_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		captureID, ts, src, dst, proto, length,
		isThreat, threatType, reason, summary, firewallAction,
		packetDetailsJSON, analysisJSON, raw,
	)
	return err
}

func ingestLANBehaviorReport(tx *sql.Tx, source, raw string) error {
	var envelope struct {
		Type      string            `json:"type"`
		Timestamp string            `json:"timestamp"`
		TotalIPs  int               `json:"total_ips"`
		Reports   []json.RawMessage `json:"reports"`
	}

	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		_, execErr := tx.Exec(
			`INSERT INTO ingest_logs (source, level, message, raw_text) VALUES (?, ?, ?, ?)`,
			source, "json_parse_error", err.Error(), raw,
		)
		return execErr
	}

	for _, reportRaw := range envelope.Reports {
		var report lanBehaviorReport
		if err := json.Unmarshal(reportRaw, &report); err != nil {
			continue
		}

		topDomainsJSON, _ := json.Marshal(report.TopDomains)
		categoryStatsJSON, _ := json.Marshal(report.CategoryStats)
		riskEventsJSON, _ := json.Marshal(report.RiskEvents)

		_, err := tx.Exec(
			`INSERT INTO lan_behavior_reports (
				ip_address, first_seen, last_seen, duration,
				total_requests, total_bytes_sent, total_bytes_received,
				unique_domains, risk_score, risk_level,
				top_domains_json, category_stats_json, risk_events_json, raw_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			report.IP, report.FirstSeen, report.LastSeen, report.Duration,
			report.TotalRequests, report.TotalBytesSent, report.TotalBytesReceived,
			report.UniqueDomains, report.RiskScore, report.RiskLevel,
			string(topDomainsJSON), string(categoryStatsJSON), string(riskEventsJSON), string(reportRaw),
		)
		if err != nil {
			return err
		}
	}

	return nil
}
