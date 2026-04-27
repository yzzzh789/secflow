package app

import (
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteTimeLayout = "2006-01-02 15:04:05"

const (
	taskKeyThreat   = "threat"
	taskKeyBehavior = "behavior"
	taskKeyLAN      = "lan-monitor"
	taskKeyNIC      = "nic-monitor"
)

const (
	taskDesiredRunning = "running"
	taskDesiredStopped = "stopped"
)

const (
	taskStatusIdle     = "idle"
	taskStatusRunning  = "running"
	taskStatusStopping = "stopping"
	taskStatusStopped  = "stopped"
	taskStatusBackoff  = "backoff"
	taskStatusFailed   = "failed"
)

var dbWriter *DBWriter
var databasePath string
var taskStateStore *TaskStateStore
var appConfig runtimeConfig

func resolveProjectRoot() string {
	if strings.TrimSpace(appConfig.ProjectRoot) != "" {
		return appConfig.ProjectRoot
	}
	return resolveProjectRootOverride()
}

func resolveDatabasePath() string {
	if strings.TrimSpace(appConfig.PacketAnalyzerDBPath) != "" {
		return appConfig.PacketAnalyzerDBPath
	}
	return resolveRuntimePath(resolveProjectRoot(), firstEnv("PACKET_ANALYZER_DB_PATH"), filepath.Join("data", "packet_analyzer.sqlite"))
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func Run(args []string) {
	appConfig = loadRuntimeConfig()
	databasePath = appConfig.PacketAnalyzerDBPath
	log.Printf("runtime config: root=%s port=%s role=%s python=%s hostAgent=%s", appConfig.ProjectRoot, appConfig.HTTPPort, appConfig.Role, appConfig.PythonBin, appConfig.HostAgentURL)
	log.Printf("SQLite DB path: %s", databasePath)

	db, err := openDatabase(databasePath)
	if err != nil {
		log.Fatalf("failed to open database %s: %v", databasePath, err)
	}
	dbWriter = NewDBWriter(db)
	taskStateStore = NewTaskStateStore(db)
	taskSupervisor = NewTaskSupervisor(taskStateStore)
	websiteSecurityServiceInstance, err = newWebsiteSecurityService(resolveWebsiteSecurityStatePath())
	if err != nil {
		log.Fatalf("failed to initialize website security service: %v", err)
	}
	defer websiteSecurityServiceInstance.Close()
	if err := taskStateStore.EnsureKnownTasks(taskKeyThreat, taskKeyBehavior, taskKeyLAN, taskKeyNIC); err != nil {
		log.Fatalf("failed to initialize managed task state: %v", err)
	}
	for _, arg := range args[1:] {
		if arg == "--init-db" {
			_ = dbWriter.Close()
			return
		}
	}

	mux := http.NewServeMux()
	registerRoutes(mux)

	taskSupervisor.RestoreManagedTasks()

	server := &http.Server{
		Addr:              appConfig.ListenAddr(),
		Handler:           controlPlaneGuard(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("Starting server on %s", appConfig.BaseURL())
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("ListenAndServe: ", err)
	}
}
