package app

import (
	"net/http"
	"sync"
	"time"
)

const (
	websiteSecurityDefaultIntervalMinutes = 15
	websiteSecurityMaxThreats             = 100
	websiteSecurityMaxLogs                = 120
)

type websiteSecurityMetrics struct {
	TotalWebsites   int `json:"totalWebsites"`
	HealthyWebsites int `json:"healthyWebsites"`
	ActiveIssues    int `json:"activeIssues"`
	HighRiskIssues  int `json:"highRiskIssues"`
	TargetWarnings  int `json:"targetWarnings"`
}

type websiteSecurityState struct {
	Websites  []websiteMonitor       `json:"websites"`
	Threats   []websiteThreat        `json:"threats"`
	Logs      []websiteLogEntry      `json:"logs"`
	Metrics   websiteSecurityMetrics `json:"metrics"`
	UpdatedAt string                 `json:"updatedAt"`
}

type websiteMonitor struct {
	ID                string               `json:"id"`
	URL               string               `json:"url"`
	IntervalMinutes   int                  `json:"intervalMinutes"`
	CreatedAt         string               `json:"createdAt"`
	LastCheckAt       string               `json:"lastCheckAt"`
	NextCheckAt       string               `json:"nextCheckAt"`
	Checking          bool                 `json:"checking"`
	SummaryStatus     string               `json:"summaryStatus"`
	SummaryMessage    string               `json:"summaryMessage"`
	LastError         string               `json:"lastError"`
	TargetRiskLevel   string               `json:"targetRiskLevel,omitempty"`
	TargetRiskReasons []string             `json:"targetRiskReasons,omitempty"`
	Checks            websiteMonitorChecks `json:"checks"`
}

type websiteMonitorChecks struct {
	Tamper       websiteContentCheck      `json:"tamper"`
	Malware      websiteIssueCheck        `json:"malware"`
	Content      websiteIssueCheck        `json:"content"`
	Availability websiteAvailabilityCheck `json:"availability"`
	Baseline     websiteIssueCheck        `json:"baseline"`
	Exposure     websiteIssueCheck        `json:"exposure"`
}

type websiteContentCheck struct {
	Status       string `json:"status"`
	LastCheckAt  string `json:"lastCheckAt"`
	Count        int    `json:"count"`
	IssueCount   int    `json:"issueCount"`
	Message      string `json:"message"`
	BaselineHash string `json:"baselineHash"`
	LastHash     string `json:"lastHash"`
}

type websiteIssueCheck struct {
	Status      string   `json:"status"`
	LastCheckAt string   `json:"lastCheckAt"`
	Count       int      `json:"count"`
	IssueCount  int      `json:"issueCount"`
	Message     string   `json:"message"`
	Findings    []string `json:"findings"`
}

type websiteAvailabilityCheck struct {
	Status           string  `json:"status"`
	LastCheckAt      string  `json:"lastCheckAt"`
	Count            int     `json:"count"`
	ResponseTimeMs   int     `json:"responseTimeMs"`
	HTTPStatus       int     `json:"httpStatus"`
	Uptime           float64 `json:"uptime"`
	SuccessCount     int     `json:"successCount"`
	FailureCount     int     `json:"failureCount"`
	SSLDaysRemaining int     `json:"sslDaysRemaining"`
	Message          string  `json:"message"`
}

type websiteThreat struct {
	ID          string `json:"id"`
	WebsiteID   string `json:"websiteId"`
	WebsiteURL  string `json:"websiteUrl"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Time        string `json:"time"`
}

type websiteLogEntry struct {
	Time    string `json:"time"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

type websiteSecurityService struct {
	mu        sync.RWMutex
	statePath string
	client    *http.Client
	checkSem  chan struct{}
	state     websiteSecurityState
	stopCh    chan struct{}
	doneCh    chan struct{}
}

type websiteFetchResult struct {
	CheckedAt        time.Time
	ResponseTimeMs   int
	StatusCode       int
	Body             []byte
	BodyLower        string
	Headers          http.Header
	SSLDaysRemaining int
}

type websiteSecurityCreateRequest struct {
	URL             string `json:"url"`
	IntervalMinutes int    `json:"intervalMinutes"`
}

var websiteSecurityServiceInstance *websiteSecurityService
