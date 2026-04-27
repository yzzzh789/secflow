package app

import (
	"testing"
	"time"
)

type fakePacketOverviewStore struct {
	gotWebsiteState websiteSecurityState
	gotActiveNICs   int
	gotHealthy      int
	gotTotal        int
}

func (s *fakePacketOverviewStore) LoadStats(websiteState websiteSecurityState, activeNICs, healthyModules, totalModules int) productOverviewStats {
	s.gotWebsiteState = websiteState
	s.gotActiveNICs = activeNICs
	s.gotHealthy = healthyModules
	s.gotTotal = totalModules
	return productOverviewStats{
		TotalPackets:      10,
		MonitoredWebsites: websiteState.Metrics.TotalWebsites,
		ActiveNICs:        activeNICs,
		HealthyModules:    healthyModules,
		TotalModules:      totalModules,
	}
}

func (s *fakePacketOverviewStore) LoadModuleStatuses(_ websiteSecurityState, activeNICs int, _ time.Time, _ int64) []productModuleStatus {
	s.gotActiveNICs = activeNICs
	return []productModuleStatus{
		{ID: "threat", Status: "healthy"},
		{ID: "nic", Status: "warning"},
	}
}

func (s *fakePacketOverviewStore) LoadThreatTypeDistribution() []labeledValue {
	return []labeledValue{{Label: "malware", Value: 2}}
}

func (s *fakePacketOverviewStore) LoadTopAssets() []assetRiskSummary {
	return []assetRiskSummary{{IP: "192.0.2.10", RiskScore: 90}}
}

func (s *fakePacketOverviewStore) LoadRecentEvents(_ websiteSecurityState) []recentEvent {
	return []recentEvent{{Source: "website_security", Severity: "high"}}
}

func (s *fakePacketOverviewStore) LoadDailyTrends() []dailyTrendPoint {
	return []dailyTrendPoint{{Date: "2026-04-26", Packets: 10}}
}

type fakeNICOverviewStore struct{}

func (fakeNICOverviewStore) LoadNICOverview() ([]nicUsageSummary, int, time.Time, int64) {
	return []nicUsageSummary{{Name: "eth0", TotalBps: 1024}}, 1, time.Unix(100, 0), 1024
}

type fakeWebsiteStateStore struct{}

func (fakeWebsiteStateStore) Snapshot() websiteSecurityState {
	return websiteSecurityState{
		Metrics: websiteSecurityMetrics{
			TotalWebsites: 3,
		},
	}
}

func TestBuildProductOverviewResponseFromStores(t *testing.T) {
	packetStore := &fakePacketOverviewStore{}

	response := buildProductOverviewResponseFromStores(packetStore, fakeNICOverviewStore{}, fakeWebsiteStateStore{})

	if response.GeneratedAt == "" {
		t.Fatal("GeneratedAt is empty")
	}
	if response.Overview.TotalPackets != 10 {
		t.Fatalf("TotalPackets = %d, want 10", response.Overview.TotalPackets)
	}
	if response.Overview.MonitoredWebsites != 3 {
		t.Fatalf("MonitoredWebsites = %d, want 3", response.Overview.MonitoredWebsites)
	}
	if response.Overview.ActiveNICs != 1 {
		t.Fatalf("ActiveNICs = %d, want 1", response.Overview.ActiveNICs)
	}
	if response.Overview.HealthyModules != 1 || response.Overview.TotalModules != 2 {
		t.Fatalf("module counts = %d/%d, want 1/2", response.Overview.HealthyModules, response.Overview.TotalModules)
	}
	if len(response.NICRanking) != 1 || response.NICRanking[0].Name != "eth0" {
		t.Fatalf("NICRanking = %#v", response.NICRanking)
	}
	if packetStore.gotActiveNICs != 1 || packetStore.gotHealthy != 1 || packetStore.gotTotal != 2 {
		t.Fatalf("packet store inputs active=%d healthy=%d total=%d", packetStore.gotActiveNICs, packetStore.gotHealthy, packetStore.gotTotal)
	}
}
