package app

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

func resolveNICDatabasePath() string {
	if strings.TrimSpace(appConfig.NICTrafficDBPath) != "" {
		return appConfig.NICTrafficDBPath
	}
	return resolveRuntimePath(resolveProjectRoot(), firstEnv("NIC_TRAFFIC_DB_PATH"), filepath.Join("data", "nic_traffic.sqlite"))
}

func openReadonlySQLite(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if err := configureSQLiteConnection(
		db,
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
	); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func queryInt(db *sql.DB, query string, args ...any) int {
	var n sql.NullInt64
	if err := db.QueryRow(query, args...).Scan(&n); err != nil || !n.Valid {
		return 0
	}
	return int(n.Int64)
}

func queryString(db *sql.DB, query string, args ...any) string {
	var s sql.NullString
	if err := db.QueryRow(query, args...).Scan(&s); err != nil || !s.Valid {
		return ""
	}
	return s.String
}

func parseSQLiteTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}

	layouts := []string{
		sqliteTimeLayout,
		time.RFC3339,
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if ts, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return ts
		}
	}

	return time.Time{}
}

func formatModuleTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.Format("2006-01-02 15:04")
}

func moduleStatusFor(ts time.Time, freshWindow, degradedWindow time.Duration) (string, string) {
	if ts.IsZero() {
		return "idle", "未运行"
	}

	age := time.Since(ts)
	switch {
	case age <= freshWindow:
		return "healthy", "正常"
	case age <= degradedWindow:
		return "stale", "延迟"
	default:
		return "idle", "未运行"
	}
}

func formatBpsShort(bps int64) string {
	units := []string{"bps", "Kbps", "Mbps", "Gbps"}
	value := float64(bps)
	index := 0
	for value >= 1000 && index < len(units)-1 {
		value /= 1000
		index++
	}
	return fmt.Sprintf("%.1f %s", value, units[index])
}
