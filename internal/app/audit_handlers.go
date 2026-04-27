package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type auditSearchEvent struct {
	CapturedAt    string          `json:"captured_at"`
	SrcIP         string          `json:"src_ip"`
	Domain        string          `json:"domain"`
	Engine        string          `json:"engine"`
	Keyword       string          `json:"keyword"`
	EvidenceLevel string          `json:"evidence_level"`
	RawJSON       json.RawMessage `json:"raw_json,omitempty"`
}

type auditViolationEvent struct {
	CapturedAt    string          `json:"captured_at"`
	SrcIP         string          `json:"src_ip"`
	Domain        string          `json:"domain"`
	ViolationType string          `json:"violation_type"`
	Severity      string          `json:"severity"`
	Reason        string          `json:"reason"`
	RawJSON       json.RawMessage `json:"raw_json,omitempty"`
}

type webAccessLogItem struct {
	ID            int    `json:"id"`
	CapturedAt    string `json:"captured_at"`
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	Domain        string `json:"domain"`
	FullHost      string `json:"full_host"`
	Category      string `json:"category"`
	AppName       string `json:"app_name"`
	Bytes         int64  `json:"bytes"`
	RequestCount  int    `json:"request_count"`
	EvidenceLevel string `json:"evidence_level"`
}

type searchAuditLogItem struct {
	ID            int    `json:"id"`
	CapturedAt    string `json:"captured_at"`
	SrcIP         string `json:"src_ip"`
	Domain        string `json:"domain"`
	Engine        string `json:"engine"`
	Keyword       string `json:"keyword"`
	EvidenceLevel string `json:"evidence_level"`
}

type violationEventItem struct {
	ID            int    `json:"id"`
	CapturedAt    string `json:"captured_at"`
	SrcIP         string `json:"src_ip"`
	Domain        string `json:"domain"`
	ViolationType string `json:"violation_type"`
	Severity      string `json:"severity"`
	Reason        string `json:"reason"`
}

type topSiteItem struct {
	Domain       string `json:"domain"`
	Visits       int    `json:"visits"`
	RequestCount int    `json:"request_count"`
	Bytes        int64  `json:"bytes"`
}

type topAppItem struct {
	AppName      string `json:"app_name"`
	Category     string `json:"category"`
	Visits       int    `json:"visits"`
	RequestCount int    `json:"request_count"`
	Bytes        int64  `json:"bytes"`
}

type countBucket struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type pagedResponse struct {
	Items    any `json:"items"`
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
	Total    int `json:"total"`
}

type violationStatsResponse struct {
	Total      int                  `json:"total"`
	ByType     []countBucket        `json:"byType"`
	BySeverity []countBucket        `json:"bySeverity"`
	Recent     []violationEventItem `json:"recent"`
}

type auditReportRequest struct {
	ReportType string `json:"reportType"`
}

type auditReportSummary struct {
	WebLogCount    int `json:"webLogCount"`
	SearchLogCount int `json:"searchLogCount"`
	ViolationCount int `json:"violationCount"`
	UniqueIPs      int `json:"uniqueIPs"`
}

type auditReportPayload struct {
	ReportType    string                 `json:"reportType"`
	PeriodStart   string                 `json:"periodStart"`
	PeriodEnd     string                 `json:"periodEnd"`
	GeneratedAt   string                 `json:"generatedAt"`
	Summary       auditReportSummary     `json:"summary"`
	TopSites      []topSiteItem          `json:"topSites"`
	TopApps       []topAppItem           `json:"topApps"`
	TopKeywords   []countBucket          `json:"topKeywords"`
	Violations    violationStatsResponse `json:"violations"`
	LatestSearch  []searchAuditLogItem   `json:"latestSearch"`
	LatestWebLogs []webAccessLogItem     `json:"latestWebLogs"`
}

type reportExportItem struct {
	ID          int    `json:"id"`
	ReportType  string `json:"reportType"`
	PeriodStart string `json:"periodStart"`
	PeriodEnd   string `json:"periodEnd"`
	FilePath    string `json:"filePath"`
	CreatedAt   string `json:"createdAt"`
	DownloadURL string `json:"downloadUrl"`
}

func normalizeAuditTimestamp(raw string) string {
	ts := parseSQLiteTime(raw)
	if ts.IsZero() {
		ts = time.Now()
	}
	return ts.Format(sqliteTimeLayout)
}

func marshalAuditRawJSON(payload any, raw json.RawMessage) string {
	if len(raw) > 0 {
		return string(raw)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func parseOptionalTimeParam(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	layouts := []string{
		sqliteTimeLayout,
		time.RFC3339,
		"2006-01-02",
	}
	for _, layout := range layouts {
		if ts, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			if layout == "2006-01-02" {
				return ts.Format("2006-01-02 00:00:00"), nil
			}
			return ts.Format(sqliteTimeLayout), nil
		}
	}
	return "", newBadRequestError("invalid time parameter")
}

func parsePositiveIntParam(raw string, defaultValue, minValue, maxValue int) int {
	value := strings.TrimSpace(raw)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	if parsed < minValue {
		return minValue
	}
	if parsed > maxValue {
		return maxValue
	}
	return parsed
}

func openAuditReadonlyDB() (*sql.DB, error) {
	return openReadonlySQLite(databasePath)
}

func queryCount(db *sql.DB, query string, args ...any) (int, error) {
	var total int
	if err := db.QueryRow(query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func buildTimeClause(column, start, end string, where *[]string, args *[]any) {
	if start != "" {
		*where = append(*where, column+" >= ?")
		*args = append(*args, start)
	}
	if end != "" {
		*where = append(*where, column+" <= ?")
		*args = append(*args, end)
	}
}

func joinWhere(where []string) string {
	if len(where) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(where, " AND ")
}

func loadTopSites(db *sql.DB, start, end string, limit int) ([]topSiteItem, error) {
	where := []string{"domain IS NOT NULL", "domain != ''"}
	args := make([]any, 0, 4)
	buildTimeClause("captured_at", start, end, &where, &args)
	args = append(args, limit)

	rows, err := db.Query(`
		SELECT
			domain,
			COUNT(*) AS visits,
			COALESCE(SUM(request_count), 0) AS request_count,
			COALESCE(SUM(bytes), 0) AS bytes
		FROM web_access_logs`+joinWhere(where)+`
		GROUP BY domain
		ORDER BY request_count DESC, bytes DESC, visits DESC
		LIMIT ?
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]topSiteItem, 0)
	for rows.Next() {
		var item topSiteItem
		if err := rows.Scan(&item.Domain, &item.Visits, &item.RequestCount, &item.Bytes); err == nil {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func loadTopApps(db *sql.DB, start, end string, limit int) ([]topAppItem, error) {
	where := []string{"COALESCE(NULLIF(app_name, ''), NULLIF(category, '')) IS NOT NULL"}
	args := make([]any, 0, 4)
	buildTimeClause("captured_at", start, end, &where, &args)
	args = append(args, limit)

	rows, err := db.Query(`
		SELECT
			COALESCE(NULLIF(app_name, ''), 'Unknown') AS app_name,
			COALESCE(NULLIF(category, ''), 'Uncategorized') AS category,
			COUNT(*) AS visits,
			COALESCE(SUM(request_count), 0) AS request_count,
			COALESCE(SUM(bytes), 0) AS bytes
		FROM web_access_logs`+joinWhere(where)+`
		GROUP BY COALESCE(NULLIF(app_name, ''), 'Unknown'), COALESCE(NULLIF(category, ''), 'Uncategorized')
		ORDER BY request_count DESC, bytes DESC, visits DESC
		LIMIT ?
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]topAppItem, 0)
	for rows.Next() {
		var item topAppItem
		if err := rows.Scan(&item.AppName, &item.Category, &item.Visits, &item.RequestCount, &item.Bytes); err == nil {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func loadKeywordBuckets(db *sql.DB, start, end string, limit int) ([]countBucket, error) {
	where := []string{"keyword IS NOT NULL", "keyword != ''"}
	args := make([]any, 0, 4)
	buildTimeClause("captured_at", start, end, &where, &args)
	args = append(args, limit)

	rows, err := db.Query(`
		SELECT keyword, COUNT(*) AS count
		FROM search_audit_logs`+joinWhere(where)+`
		GROUP BY keyword
		ORDER BY count DESC
		LIMIT ?
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]countBucket, 0)
	for rows.Next() {
		var item countBucket
		if err := rows.Scan(&item.Name, &item.Count); err == nil {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func loadViolationStats(db *sql.DB, start, end string) (violationStatsResponse, error) {
	where := make([]string, 0, 2)
	args := make([]any, 0, 2)
	buildTimeClause("captured_at", start, end, &where, &args)

	total, err := queryCount(db, `SELECT COUNT(*) FROM violation_events`+joinWhere(where), args...)
	if err != nil {
		return violationStatsResponse{}, err
	}

	byType, err := loadViolationBuckets(db, "violation_type", where, args)
	if err != nil {
		return violationStatsResponse{}, err
	}
	bySeverity, err := loadViolationBuckets(db, "severity", where, args)
	if err != nil {
		return violationStatsResponse{}, err
	}
	recent, err := loadRecentViolations(db, start, end, 20)
	if err != nil {
		return violationStatsResponse{}, err
	}

	return violationStatsResponse{
		Total:      total,
		ByType:     byType,
		BySeverity: bySeverity,
		Recent:     recent,
	}, nil
}

func loadViolationBuckets(db *sql.DB, column string, where []string, args []any) ([]countBucket, error) {
	rows, err := db.Query(`
		SELECT COALESCE(NULLIF(`+column+`, ''), 'unknown') AS name, COUNT(*) AS count
		FROM violation_events`+joinWhere(where)+`
		GROUP BY COALESCE(NULLIF(`+column+`, ''), 'unknown')
		ORDER BY count DESC
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]countBucket, 0)
	for rows.Next() {
		var item countBucket
		if err := rows.Scan(&item.Name, &item.Count); err == nil {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func loadRecentViolations(db *sql.DB, start, end string, limit int) ([]violationEventItem, error) {
	where := make([]string, 0, 2)
	args := make([]any, 0, 4)
	buildTimeClause("captured_at", start, end, &where, &args)
	args = append(args, limit)

	rows, err := db.Query(`
		SELECT id, captured_at, src_ip, domain, violation_type, severity, reason
		FROM violation_events`+joinWhere(where)+`
		ORDER BY captured_at DESC, id DESC
		LIMIT ?
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]violationEventItem, 0)
	for rows.Next() {
		var item violationEventItem
		if err := rows.Scan(&item.ID, &item.CapturedAt, &item.SrcIP, &item.Domain, &item.ViolationType, &item.Severity, &item.Reason); err == nil {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func handleAuditWebLogs(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	start, err := parseOptionalTimeParam(r.URL.Query().Get("start"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}
	end, err := parseOptionalTimeParam(r.URL.Query().Get("end"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}

	page := parsePositiveIntParam(r.URL.Query().Get("page"), 1, 1, 100000)
	pageSize := parsePositiveIntParam(r.URL.Query().Get("pageSize"), 20, 1, 200)
	offset := (page - 1) * pageSize

	db, err := openAuditReadonlyDB()
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer db.Close()

	where := make([]string, 0, 6)
	args := make([]any, 0, 8)
	buildTimeClause("captured_at", start, end, &where, &args)

	if srcIP := strings.TrimSpace(r.URL.Query().Get("src_ip")); srcIP != "" {
		where = append(where, "src_ip = ?")
		args = append(args, srcIP)
	}
	if domain := strings.TrimSpace(r.URL.Query().Get("domain")); domain != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+domain+"%")
	}
	if category := strings.TrimSpace(r.URL.Query().Get("category")); category != "" {
		where = append(where, "category = ?")
		args = append(args, category)
	}

	total, err := queryCount(db, `SELECT COUNT(*) FROM web_access_logs`+joinWhere(where), args...)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}

	queryArgs := append(append([]any{}, args...), pageSize, offset)
	rows, err := db.Query(`
		SELECT id, captured_at, src_ip, dst_ip, domain, full_host, category, app_name, bytes, request_count, evidence_level
		FROM web_access_logs`+joinWhere(where)+`
		ORDER BY captured_at DESC, id DESC
		LIMIT ? OFFSET ?
	`, queryArgs...)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	items := make([]webAccessLogItem, 0)
	for rows.Next() {
		var item webAccessLogItem
		if err := rows.Scan(
			&item.ID,
			&item.CapturedAt,
			&item.SrcIP,
			&item.DstIP,
			&item.Domain,
			&item.FullHost,
			&item.Category,
			&item.AppName,
			&item.Bytes,
			&item.RequestCount,
			&item.EvidenceLevel,
		); err == nil {
			items = append(items, item)
		}
	}

	writeJSON(w, http.StatusOK, pagedResponse{
		Items:    items,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	})
}

func handleAuditSearchLogs(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	start, err := parseOptionalTimeParam(r.URL.Query().Get("start"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}
	end, err := parseOptionalTimeParam(r.URL.Query().Get("end"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}

	page := parsePositiveIntParam(r.URL.Query().Get("page"), 1, 1, 100000)
	pageSize := parsePositiveIntParam(r.URL.Query().Get("pageSize"), 20, 1, 200)
	offset := (page - 1) * pageSize

	db, err := openAuditReadonlyDB()
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer db.Close()

	where := make([]string, 0, 6)
	args := make([]any, 0, 8)
	buildTimeClause("captured_at", start, end, &where, &args)

	if srcIP := strings.TrimSpace(r.URL.Query().Get("src_ip")); srcIP != "" {
		where = append(where, "src_ip = ?")
		args = append(args, srcIP)
	}
	if domain := strings.TrimSpace(r.URL.Query().Get("domain")); domain != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+domain+"%")
	}
	if engine := strings.TrimSpace(r.URL.Query().Get("engine")); engine != "" {
		where = append(where, "engine = ?")
		args = append(args, engine)
	}
	if keyword := strings.TrimSpace(r.URL.Query().Get("keyword")); keyword != "" {
		where = append(where, "keyword LIKE ?")
		args = append(args, "%"+keyword+"%")
	}

	total, err := queryCount(db, `SELECT COUNT(*) FROM search_audit_logs`+joinWhere(where), args...)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}

	queryArgs := append(append([]any{}, args...), pageSize, offset)
	rows, err := db.Query(`
		SELECT id, captured_at, src_ip, domain, engine, keyword, evidence_level
		FROM search_audit_logs`+joinWhere(where)+`
		ORDER BY captured_at DESC, id DESC
		LIMIT ? OFFSET ?
	`, queryArgs...)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	items := make([]searchAuditLogItem, 0)
	for rows.Next() {
		var item searchAuditLogItem
		if err := rows.Scan(
			&item.ID,
			&item.CapturedAt,
			&item.SrcIP,
			&item.Domain,
			&item.Engine,
			&item.Keyword,
			&item.EvidenceLevel,
		); err == nil {
			items = append(items, item)
		}
	}

	writeJSON(w, http.StatusOK, pagedResponse{
		Items:    items,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	})
}

func handleAuditTopSites(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	start, err := parseOptionalTimeParam(r.URL.Query().Get("start"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}
	end, err := parseOptionalTimeParam(r.URL.Query().Get("end"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}
	limit := parsePositiveIntParam(r.URL.Query().Get("limit"), 20, 1, 100)

	db, err := openAuditReadonlyDB()
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer db.Close()

	items, err := loadTopSites(db, start, end, limit)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func handleAuditTopApps(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	start, err := parseOptionalTimeParam(r.URL.Query().Get("start"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}
	end, err := parseOptionalTimeParam(r.URL.Query().Get("end"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}
	limit := parsePositiveIntParam(r.URL.Query().Get("limit"), 20, 1, 100)

	db, err := openAuditReadonlyDB()
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer db.Close()

	items, err := loadTopApps(db, start, end, limit)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func handleAuditViolationStats(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	start, err := parseOptionalTimeParam(r.URL.Query().Get("start"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}
	end, err := parseOptionalTimeParam(r.URL.Query().Get("end"))
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}

	db, err := openAuditReadonlyDB()
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer db.Close()

	stats, err := loadViolationStats(db, start, end)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func computeReportWindow(reportType string, now time.Time) (time.Time, time.Time, error) {
	now = now.In(time.Local)
	switch strings.ToLower(strings.TrimSpace(reportType)) {
	case "weekly":
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, -6)
		return start, now, nil
	case "monthly":
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		return start, now, nil
	default:
		return time.Time{}, time.Time{}, newBadRequestError("unsupported reportType")
	}
}

func buildAuditReportPayload(db *sql.DB, reportType, start, end string) (auditReportPayload, error) {
	webLogCount, err := queryCount(db, `SELECT COUNT(*) FROM web_access_logs WHERE captured_at >= ? AND captured_at <= ?`, start, end)
	if err != nil {
		return auditReportPayload{}, err
	}
	searchLogCount, err := queryCount(db, `SELECT COUNT(*) FROM search_audit_logs WHERE captured_at >= ? AND captured_at <= ?`, start, end)
	if err != nil {
		return auditReportPayload{}, err
	}
	violationCount, err := queryCount(db, `SELECT COUNT(*) FROM violation_events WHERE captured_at >= ? AND captured_at <= ?`, start, end)
	if err != nil {
		return auditReportPayload{}, err
	}
	uniqueIPs, err := queryCount(db, `
		SELECT COUNT(DISTINCT src_ip)
		FROM web_access_logs
		WHERE captured_at >= ? AND captured_at <= ? AND src_ip IS NOT NULL AND src_ip != ''
	`, start, end)
	if err != nil {
		return auditReportPayload{}, err
	}

	topSites, err := loadTopSites(db, start, end, 10)
	if err != nil {
		return auditReportPayload{}, err
	}
	topApps, err := loadTopApps(db, start, end, 10)
	if err != nil {
		return auditReportPayload{}, err
	}
	topKeywords, err := loadKeywordBuckets(db, start, end, 10)
	if err != nil {
		return auditReportPayload{}, err
	}
	violations, err := loadViolationStats(db, start, end)
	if err != nil {
		return auditReportPayload{}, err
	}

	latestSearch, err := loadSearchLogsForReport(db, start, end, 20)
	if err != nil {
		return auditReportPayload{}, err
	}
	latestWebLogs, err := loadWebLogsForReport(db, start, end, 20)
	if err != nil {
		return auditReportPayload{}, err
	}

	return auditReportPayload{
		ReportType:  reportType,
		PeriodStart: start,
		PeriodEnd:   end,
		GeneratedAt: time.Now().Format(sqliteTimeLayout),
		Summary: auditReportSummary{
			WebLogCount:    webLogCount,
			SearchLogCount: searchLogCount,
			ViolationCount: violationCount,
			UniqueIPs:      uniqueIPs,
		},
		TopSites:      topSites,
		TopApps:       topApps,
		TopKeywords:   topKeywords,
		Violations:    violations,
		LatestSearch:  latestSearch,
		LatestWebLogs: latestWebLogs,
	}, nil
}

func loadSearchLogsForReport(db *sql.DB, start, end string, limit int) ([]searchAuditLogItem, error) {
	rows, err := db.Query(`
		SELECT id, captured_at, src_ip, domain, engine, keyword, evidence_level
		FROM search_audit_logs
		WHERE captured_at >= ? AND captured_at <= ?
		ORDER BY captured_at DESC, id DESC
		LIMIT ?
	`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]searchAuditLogItem, 0)
	for rows.Next() {
		var item searchAuditLogItem
		if err := rows.Scan(&item.ID, &item.CapturedAt, &item.SrcIP, &item.Domain, &item.Engine, &item.Keyword, &item.EvidenceLevel); err == nil {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func loadWebLogsForReport(db *sql.DB, start, end string, limit int) ([]webAccessLogItem, error) {
	rows, err := db.Query(`
		SELECT id, captured_at, src_ip, dst_ip, domain, full_host, category, app_name, bytes, request_count, evidence_level
		FROM web_access_logs
		WHERE captured_at >= ? AND captured_at <= ?
		ORDER BY captured_at DESC, id DESC
		LIMIT ?
	`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]webAccessLogItem, 0)
	for rows.Next() {
		var item webAccessLogItem
		if err := rows.Scan(&item.ID, &item.CapturedAt, &item.SrcIP, &item.DstIP, &item.Domain, &item.FullHost, &item.Category, &item.AppName, &item.Bytes, &item.RequestCount, &item.EvidenceLevel); err == nil {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func reportOutputPath(reportType string, generatedAt time.Time) string {
	fileName := fmt.Sprintf("%s-%s.json", reportType, generatedAt.Format("20060102-150405"))
	return resolveRuntimePath(resolveProjectRoot(), "", filepath.Join("data", "reports", fileName))
}

func handleGenerateAuditReport(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var req auditReportRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}

	reportType := strings.ToLower(strings.TrimSpace(req.ReportType))
	if reportType == "" {
		reportType = "weekly"
	}

	startTime, endTime, err := computeReportWindow(reportType, time.Now())
	if err != nil {
		writeHTTPError(w, err, http.StatusBadRequest)
		return
	}
	start := startTime.Format(sqliteTimeLayout)
	end := endTime.Format(sqliteTimeLayout)

	db, err := openDatabase(databasePath)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer db.Close()

	payload, err := buildAuditReportPayload(db, reportType, start, end)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}

	generatedAt := time.Now()
	outputPath := reportOutputPath(reportType, generatedAt)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}

	summaryJSON, err := json.Marshal(payload.Summary)
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}

	result, err := db.Exec(`
		INSERT INTO report_exports (
			report_type, period_start, period_end, file_path, created_at, summary_json
		) VALUES (?, ?, ?, ?, ?, ?)
	`, reportType, start, end, outputPath, generatedAt.Format(sqliteTimeLayout), string(summaryJSON))
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}

	reportID, _ := result.LastInsertId()
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          reportID,
		"reportType":  reportType,
		"periodStart": start,
		"periodEnd":   end,
		"filePath":    outputPath,
		"downloadUrl": fmt.Sprintf("/api/reports/download?id=%d", reportID),
	})
}

func loadLatestReportExport(db *sql.DB, reportType string) (reportExportItem, error) {
	var item reportExportItem
	row := db.QueryRow(`
		SELECT id, report_type, period_start, period_end, file_path, created_at
		FROM report_exports
		WHERE report_type = ?
		ORDER BY created_at DESC, id DESC
		LIMIT 1
	`, reportType)
	if err := row.Scan(&item.ID, &item.ReportType, &item.PeriodStart, &item.PeriodEnd, &item.FilePath, &item.CreatedAt); err != nil {
		return reportExportItem{}, err
	}
	item.DownloadURL = fmt.Sprintf("/api/reports/download?id=%d", item.ID)
	return item, nil
}

func handleLatestAuditReport(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	reportType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("reportType")))
	if reportType == "" {
		reportType = "weekly"
	}

	db, err := openAuditReadonlyDB()
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer db.Close()

	item, err := loadLatestReportExport(db, reportType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "report not found", http.StatusNotFound)
			return
		}
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func handleDownloadAuditReport(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	id := parsePositiveIntParam(r.URL.Query().Get("id"), 0, 0, 1_000_000)
	if id <= 0 {
		http.Error(w, "missing report id", http.StatusBadRequest)
		return
	}

	db, err := openAuditReadonlyDB()
	if err != nil {
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var filePath string
	var reportType string
	var createdAt string
	err = db.QueryRow(`
		SELECT file_path, report_type, created_at
		FROM report_exports
		WHERE id = ?
	`, id).Scan(&filePath, &reportType, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "report not found", http.StatusNotFound)
			return
		}
		writeHTTPError(w, err, http.StatusInternalServerError)
		return
	}

	fileName := fmt.Sprintf("%s-%s.json", reportType, strings.ReplaceAll(createdAt, ":", ""))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	http.ServeFile(w, r, filePath)
}
