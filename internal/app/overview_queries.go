package app

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

func loadThreatTypeDistribution(db *sql.DB) []labeledValue {
	rows, err := db.Query(`
		SELECT COALESCE(NULLIF(threat_type, ''), '未分类') AS label, COUNT(*) AS value
		FROM packet_events
		WHERE is_threat = 1
		GROUP BY COALESCE(NULLIF(threat_type, ''), '未分类')
		ORDER BY value DESC
		LIMIT 6
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var items []labeledValue
	for rows.Next() {
		var item labeledValue
		if err := rows.Scan(&item.Label, &item.Value); err == nil {
			items = append(items, item)
		}
	}
	return items
}

func loadThreatEventCountByIP(db *sql.DB) map[string]int {
	rows, err := db.Query(`
		SELECT ip, SUM(cnt) AS total FROM (
			SELECT src_ip AS ip, COUNT(*) AS cnt
			FROM packet_events
			WHERE is_threat = 1 AND src_ip IS NOT NULL AND src_ip != '' AND src_ip != 'N/A'
			GROUP BY src_ip
			UNION ALL
			SELECT dst_ip AS ip, COUNT(*) AS cnt
			FROM packet_events
			WHERE is_threat = 1 AND dst_ip IS NOT NULL AND dst_ip != '' AND dst_ip != 'N/A'
			GROUP BY dst_ip
		)
		GROUP BY ip
	`)
	if err != nil {
		return map[string]int{}
	}
	defer rows.Close()

	result := make(map[string]int)
	for rows.Next() {
		var ip string
		var count int
		if err := rows.Scan(&ip, &count); err == nil {
			result[ip] = count
		}
	}
	return result
}

func loadTopAssets(db *sql.DB) []assetRiskSummary {
	threatCounts := loadThreatEventCountByIP(db)

	rows, err := db.Query(`
		SELECT
			ip_address,
			MAX(risk_score) AS risk_score,
			MAX(CASE risk_level
				WHEN 'high' THEN 3
				WHEN 'medium' THEN 2
				WHEN 'low' THEN 1
				ELSE 0
			END) AS severity,
			MAX(total_requests) AS total_requests,
			MAX(unique_domains) AS unique_domains,
			MAX(captured_at) AS captured_at
		FROM lan_behavior_reports
		GROUP BY ip_address
		ORDER BY severity DESC, risk_score DESC, total_requests DESC
		LIMIT 8
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var items []assetRiskSummary
	for rows.Next() {
		var item assetRiskSummary
		var severity int
		if err := rows.Scan(&item.IP, &item.RiskScore, &severity, &item.Requests, &item.UniqueDomains, &item.LastSeen); err != nil {
			continue
		}

		switch severity {
		case 3:
			item.RiskLevel = "high"
		case 2:
			item.RiskLevel = "medium"
		default:
			item.RiskLevel = "low"
		}
		item.ThreatEvents = threatCounts[item.IP]
		items = append(items, item)
	}

	return items
}

func loadRecentEvents(db *sql.DB, websiteState websiteSecurityState) []recentEvent {
	var events []recentEvent

	packetRows, err := db.Query(`
		SELECT captured_at, COALESCE(NULLIF(threat_type, ''), '未分类'), COALESCE(NULLIF(summary, ''), '检测到可疑流量'), src_ip, dst_ip
		FROM packet_events
		WHERE is_threat = 1
		ORDER BY captured_at DESC
		LIMIT 6
	`)
	if err == nil {
		defer packetRows.Close()
		for packetRows.Next() {
			var capturedAt, threatType, summary, srcIP, dstIP string
			if err := packetRows.Scan(&capturedAt, &threatType, &summary, &srcIP, &dstIP); err != nil {
				continue
			}
			ts := parseSQLiteTime(capturedAt)
			events = append(events, recentEvent{
				At:        formatModuleTime(ts),
				Timestamp: ts.Unix(),
				Source:    "threat_detection",
				Severity:  "high",
				Title:     threatType,
				Detail:    fmt.Sprintf("%s -> %s | %s", srcIP, dstIP, summary),
			})
		}
	}

	behaviorRows, err := db.Query(`
		SELECT last_seen, COALESCE(NULLIF(main_service, ''), main_domain), behavior_label, risk_level, request_count
		FROM behavior_sessions
		WHERE risk_level IN ('high', 'medium')
		ORDER BY last_seen DESC
		LIMIT 5
	`)
	if err == nil {
		defer behaviorRows.Close()
		for behaviorRows.Next() {
			var lastSeen, name, label, level string
			var requests int
			if err := behaviorRows.Scan(&lastSeen, &name, &label, &level, &requests); err != nil {
				continue
			}
			ts := parseSQLiteTime(lastSeen)
			events = append(events, recentEvent{
				At:        formatModuleTime(ts),
				Timestamp: ts.Unix(),
				Source:    "behavior_analysis",
				Severity:  level,
				Title:     fmt.Sprintf("行为风险: %s", name),
				Detail:    fmt.Sprintf("%s | %d 请求", label, requests),
			})
		}
	}

	lanRows, err := db.Query(`
		SELECT captured_at, ip_address, risk_level, risk_score, total_requests
		FROM lan_behavior_reports
		WHERE risk_level IN ('high', 'medium')
		ORDER BY captured_at DESC
		LIMIT 5
	`)
	if err == nil {
		defer lanRows.Close()
		for lanRows.Next() {
			var capturedAt, ip, level string
			var score, requests int
			if err := lanRows.Scan(&capturedAt, &ip, &level, &score, &requests); err != nil {
				continue
			}
			ts := parseSQLiteTime(capturedAt)
			events = append(events, recentEvent{
				At:        formatModuleTime(ts),
				Timestamp: ts.Unix(),
				Source:    "lan_monitor",
				Severity:  level,
				Title:     fmt.Sprintf("资产风险: %s", ip),
				Detail:    fmt.Sprintf("风险评分 %d | %d 请求", score, requests),
			})
		}
	}

	logRows, err := db.Query(`
		SELECT created_at, source, level, COALESCE(NULLIF(message, ''), raw_text)
		FROM ingest_logs
		WHERE level IN ('error', 'warning')
		ORDER BY created_at DESC
		LIMIT 5
	`)
	if err == nil {
		defer logRows.Close()
		for logRows.Next() {
			var createdAt, source, level, message string
			if err := logRows.Scan(&createdAt, &source, &level, &message); err != nil {
				continue
			}
			ts := parseSQLiteTime(createdAt)
			events = append(events, recentEvent{
				At:        formatModuleTime(ts),
				Timestamp: ts.Unix(),
				Source:    source,
				Severity:  level,
				Title:     "系统告警",
				Detail:    message,
			})
		}
	}

	for _, threat := range websiteState.Threats {
		ts := parseRFC3339(threat.Time)
		if ts.IsZero() {
			ts = time.Now()
		}

		detail := strings.TrimSpace(threat.Description)
		if threat.WebsiteURL != "" {
			detail = fmt.Sprintf("%s | %s", threat.WebsiteURL, detail)
		}

		events = append(events, recentEvent{
			At:        formatModuleTime(ts),
			Timestamp: ts.Unix(),
			Source:    "website_security",
			Severity:  threat.Severity,
			Title:     threat.Title,
			Detail:    detail,
		})
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp > events[j].Timestamp
	})
	if len(events) > 12 {
		events = events[:12]
	}
	return events
}

func loadDailyTrends(db *sql.DB) []dailyTrendPoint {
	packetMap := make(map[string]int)
	threatMap := make(map[string]int)
	behaviorMap := make(map[string]int)
	lanMap := make(map[string]int)

	packetRows, err := db.Query(`
		SELECT substr(captured_at, 1, 10) AS day, COUNT(*) AS packets, SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) AS threats
		FROM packet_events
		WHERE captured_at >= datetime('now', '-6 days')
		GROUP BY substr(captured_at, 1, 10)
	`)
	if err == nil {
		defer packetRows.Close()
		for packetRows.Next() {
			var day string
			var packets, threats int
			if err := packetRows.Scan(&day, &packets, &threats); err == nil {
				packetMap[day] = packets
				threatMap[day] = threats
			}
		}
	}

	behaviorRows, err := db.Query(`
		SELECT substr(last_seen, 1, 10) AS day, COUNT(*) AS behaviors
		FROM behavior_sessions
		WHERE last_seen >= datetime('now', '-6 days')
		GROUP BY substr(last_seen, 1, 10)
	`)
	if err == nil {
		defer behaviorRows.Close()
		for behaviorRows.Next() {
			var day string
			var count int
			if err := behaviorRows.Scan(&day, &count); err == nil {
				behaviorMap[day] = count
			}
		}
	}

	lanRows, err := db.Query(`
		SELECT substr(captured_at, 1, 10) AS day, COUNT(*) AS reports
		FROM lan_behavior_reports
		WHERE captured_at >= datetime('now', '-6 days')
		GROUP BY substr(captured_at, 1, 10)
	`)
	if err == nil {
		defer lanRows.Close()
		for lanRows.Next() {
			var day string
			var count int
			if err := lanRows.Scan(&day, &count); err == nil {
				lanMap[day] = count
			}
		}
	}

	var points []dailyTrendPoint
	now := time.Now()
	for i := 6; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		points = append(points, dailyTrendPoint{
			Date:       day,
			Packets:    packetMap[day],
			Threats:    threatMap[day],
			Behaviors:  behaviorMap[day],
			LANReports: lanMap[day],
		})
	}
	return points
}

func loadNICRanking(nicDB *sql.DB) ([]nicUsageSummary, int, time.Time, int64) {
	latestTs := queryInt(nicDB, `SELECT COALESCE(MAX(ts), 0) FROM traffic`)
	if latestTs == 0 {
		return nil, 0, time.Time{}, 0
	}

	activeNICs := queryInt(nicDB, `SELECT COUNT(*) FROM traffic WHERE ts = ? AND (rx_bps + tx_bps) > 0`, latestTs)

	rows, err := nicDB.Query(`
		SELECT nic, rx_bps, tx_bps, (rx_bps + tx_bps) AS total_bps
		FROM traffic
		WHERE ts = ?
		ORDER BY total_bps DESC
		LIMIT 6
	`, latestTs)
	if err != nil {
		return nil, activeNICs, time.Unix(int64(latestTs), 0), 0
	}
	defer rows.Close()

	var items []nicUsageSummary
	var peak int64
	for rows.Next() {
		var item nicUsageSummary
		if err := rows.Scan(&item.Name, &item.RXBps, &item.TXBps, &item.TotalBps); err != nil {
			continue
		}
		item.TotalMbps = float64(item.TotalBps) / 1000.0 / 1000.0
		if item.TotalBps > peak {
			peak = item.TotalBps
		}
		items = append(items, item)
	}

	return items, activeNICs, time.Unix(int64(latestTs), 0), peak
}
