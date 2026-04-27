package app

import (
	"database/sql"
	"log"
	"time"
)

type PacketOverviewStore interface {
	LoadStats(websiteState websiteSecurityState, activeNICs, healthyModules, totalModules int) productOverviewStats
	LoadModuleStatuses(websiteState websiteSecurityState, activeNICs int, nicUpdatedAt time.Time, nicPeak int64) []productModuleStatus
	LoadThreatTypeDistribution() []labeledValue
	LoadTopAssets() []assetRiskSummary
	LoadRecentEvents(websiteState websiteSecurityState) []recentEvent
	LoadDailyTrends() []dailyTrendPoint
}

type NICOverviewStore interface {
	LoadNICOverview() ([]nicUsageSummary, int, time.Time, int64)
}

type WebsiteStateStore interface {
	Snapshot() websiteSecurityState
}

type sqlitePacketOverviewStore struct {
	db *sql.DB
}

func newSQLitePacketOverviewStore(db *sql.DB) sqlitePacketOverviewStore {
	return sqlitePacketOverviewStore{db: db}
}

func (s sqlitePacketOverviewStore) LoadStats(websiteState websiteSecurityState, activeNICs, healthyModules, totalModules int) productOverviewStats {
	return loadProductOverviewStats(s.db, websiteState, activeNICs, healthyModules, totalModules)
}

func (s sqlitePacketOverviewStore) LoadModuleStatuses(websiteState websiteSecurityState, activeNICs int, nicUpdatedAt time.Time, nicPeak int64) []productModuleStatus {
	return buildModuleStatuses(s.db, websiteState, activeNICs, nicUpdatedAt, nicPeak)
}

func (s sqlitePacketOverviewStore) LoadThreatTypeDistribution() []labeledValue {
	return loadThreatTypeDistribution(s.db)
}

func (s sqlitePacketOverviewStore) LoadTopAssets() []assetRiskSummary {
	return loadTopAssets(s.db)
}

func (s sqlitePacketOverviewStore) LoadRecentEvents(websiteState websiteSecurityState) []recentEvent {
	return loadRecentEvents(s.db, websiteState)
}

func (s sqlitePacketOverviewStore) LoadDailyTrends() []dailyTrendPoint {
	return loadDailyTrends(s.db)
}

type sqliteNICOverviewStore struct {
	path string
}

func newSQLiteNICOverviewStore(path string) sqliteNICOverviewStore {
	return sqliteNICOverviewStore{path: path}
}

func (s sqliteNICOverviewStore) LoadNICOverview() ([]nicUsageSummary, int, time.Time, int64) {
	nicDB, err := openReadonlySQLite(s.path)
	if err != nil {
		log.Printf("product overview: NIC database unavailable: %v", err)
		return nil, 0, time.Time{}, 0
	}
	defer nicDB.Close()
	return loadNICRanking(nicDB)
}

type websiteServiceStateStore struct {
	service *websiteSecurityService
}

func newWebsiteServiceStateStore(service *websiteSecurityService) websiteServiceStateStore {
	return websiteServiceStateStore{service: service}
}

func (s websiteServiceStateStore) Snapshot() websiteSecurityState {
	if s.service == nil {
		return websiteSecurityState{}
	}
	return s.service.Snapshot()
}
