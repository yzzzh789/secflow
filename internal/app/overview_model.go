package app

import (
	"sync"
	"time"
)

type productOverviewResponse struct {
	GeneratedAt  string                `json:"generatedAt"`
	Overview     productOverviewStats  `json:"overview"`
	Modules      []productModuleStatus `json:"modules"`
	ThreatTypes  []labeledValue        `json:"threatTypes"`
	TopAssets    []assetRiskSummary    `json:"topAssets"`
	RecentEvents []recentEvent         `json:"recentEvents"`
	DailyTrends  []dailyTrendPoint     `json:"dailyTrends"`
	NICRanking   []nicUsageSummary     `json:"nicRanking"`
}

type productOverviewStats struct {
	TotalPackets       int     `json:"totalPackets"`
	ThreatEvents       int     `json:"threatEvents"`
	ThreatRate         float64 `json:"threatRate"`
	BehaviorSessions   int     `json:"behaviorSessions"`
	LANAssets          int     `json:"lanAssets"`
	HighRiskAssets     int     `json:"highRiskAssets"`
	MonitoredWebsites  int     `json:"monitoredWebsites"`
	WebsiteThreats     int     `json:"websiteThreats"`
	WebsiteIssues      int     `json:"websiteIssues"`
	ActiveNICs         int     `json:"activeNICs"`
	HealthyModules     int     `json:"healthyModules"`
	TotalModules       int     `json:"totalModules"`
	MonitoringCoverage string  `json:"monitoringCoverage"`
}

type productModuleStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	StatusLabel string `json:"statusLabel"`
	UpdatedAt   string `json:"updatedAt"`
	URL         string `json:"url"`
	Metric      string `json:"metric"`
	Detail      string `json:"detail"`
}

type labeledValue struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

type assetRiskSummary struct {
	IP            string `json:"ip"`
	RiskScore     int    `json:"riskScore"`
	RiskLevel     string `json:"riskLevel"`
	ThreatEvents  int    `json:"threatEvents"`
	Requests      int    `json:"requests"`
	UniqueDomains int    `json:"uniqueDomains"`
	LastSeen      string `json:"lastSeen"`
}

type recentEvent struct {
	At        string `json:"at"`
	Timestamp int64  `json:"timestamp"`
	Source    string `json:"source"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
}

type dailyTrendPoint struct {
	Date       string `json:"date"`
	Packets    int    `json:"packets"`
	Threats    int    `json:"threats"`
	Behaviors  int    `json:"behaviors"`
	LANReports int    `json:"lanReports"`
}

type nicUsageSummary struct {
	Name      string  `json:"name"`
	RXBps     int64   `json:"rxBps"`
	TXBps     int64   `json:"txBps"`
	TotalBps  int64   `json:"totalBps"`
	TotalMbps float64 `json:"totalMbps"`
}

type jsonResponseCache struct {
	mu        sync.RWMutex
	payload   []byte
	expiresAt time.Time
}

func (c *jsonResponseCache) load(now time.Time) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.payload) == 0 || !now.Before(c.expiresAt) {
		return nil, false
	}
	return c.payload, true
}

func (c *jsonResponseCache) store(payload []byte, ttl time.Duration) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.payload = payload
	c.expiresAt = time.Now().Add(ttl)
	return c.payload
}

const (
	productOverviewCacheTTL = 5 * time.Second
)

var (
	productOverviewCache jsonResponseCache
)
