package app

import (
	"path/filepath"
	"testing"
)

func TestOpenDatabaseInitializesMainSchema(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "secflow.sqlite")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error = %v", err)
	}
	defer db.Close()

	for _, tableName := range []string{"packet_events", "behavior_sessions", "managed_tasks"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, tableName).Scan(&count); err != nil {
			t.Fatalf("sqlite_master query for %s failed: %v", tableName, err)
		}
		if count != 1 {
			t.Fatalf("expected table %s to exist, got count=%d", tableName, count)
		}
	}
}
