package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func resolveWebsiteSecurityStatePath() string {
	if strings.TrimSpace(appConfig.WebsiteSecurityStatePath) != "" {
		return appConfig.WebsiteSecurityStatePath
	}
	return resolveRuntimePath(resolveProjectRoot(), firstEnv("WEBSITE_SECURITY_STATE_PATH"), filepath.Join("data", "website_security_state.json"))
}

func newWebsiteSecurityService(statePath string) (*websiteSecurityService, error) {
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return nil, err
	}

	service := &websiteSecurityService{
		statePath: statePath,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		checkSem: make(chan struct{}, normalizeWebsiteSecurityCheckConcurrency(appConfig.WebsiteSecurityCheckConcurrency)),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}

	if err := service.load(); err != nil {
		return nil, err
	}

	service.mu.Lock()
	service.appendLogLocked("system", "website security service started")
	if err := service.saveLocked(); err != nil {
		service.mu.Unlock()
		return nil, err
	}
	service.mu.Unlock()

	go service.schedulerLoop()
	return service, nil
}

func (s *websiteSecurityService) Close() {
	close(s.stopCh)
	<-s.doneCh
}

func (s *websiteSecurityService) load() error {
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			s.state = websiteSecurityState{}
			s.recomputeMetricsLocked()
			return nil
		}
		return err
	}

	var loaded websiteSecurityState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return err
	}

	for i := range loaded.Websites {
		if loaded.Websites[i].IntervalMinutes <= 0 {
			loaded.Websites[i].IntervalMinutes = websiteSecurityDefaultIntervalMinutes
		}
		loaded.Websites[i].Checking = false
		if strings.TrimSpace(loaded.Websites[i].NextCheckAt) == "" {
			loaded.Websites[i].NextCheckAt = time.Now().Add(15 * time.Second).Format(time.RFC3339)
		}
	}

	s.state = loaded
	s.recomputeMetricsLocked()
	return nil
}

func (s *websiteSecurityService) saveLocked() error {
	s.recomputeMetricsLocked()
	s.state.UpdatedAt = time.Now().Format(time.RFC3339)

	payload, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}

	tempPath := s.statePath + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tempPath, s.statePath)
}

func (s *websiteSecurityService) schedulerLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer close(s.doneCh)

	for {
		select {
		case <-ticker.C:
			s.runDueChecks()
		case <-s.stopCh:
			return
		}
	}
}

func (s *websiteSecurityService) Snapshot() websiteSecurityState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	raw, err := json.Marshal(s.state)
	if err != nil {
		return websiteSecurityState{}
	}

	var snapshot websiteSecurityState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return websiteSecurityState{}
	}
	return snapshot
}

func (s *websiteSecurityService) AddWebsite(rawURL string, intervalMinutes int) (websiteMonitor, error) {
	normalizedURL, err := normalizeWebsiteURL(rawURL)
	if err != nil {
		return websiteMonitor{}, err
	}

	if intervalMinutes <= 0 {
		intervalMinutes = websiteSecurityDefaultIntervalMinutes
	}

	now := time.Now().Format(time.RFC3339)
	pendingMessage := "waiting for first check"
	monitor := websiteMonitor{
		ID:              generateWebsiteSecurityID("site"),
		URL:             normalizedURL,
		IntervalMinutes: intervalMinutes,
		CreatedAt:       now,
		NextCheckAt:     time.Now().Format(time.RFC3339),
		SummaryStatus:   "pending",
		SummaryMessage:  pendingMessage,
		Checks: websiteMonitorChecks{
			Tamper:       websiteContentCheck{Status: "pending", Message: pendingMessage},
			Malware:      websiteIssueCheck{Status: "pending", Message: pendingMessage},
			Content:      websiteIssueCheck{Status: "pending", Message: pendingMessage},
			Availability: websiteAvailabilityCheck{Status: "pending", Message: pendingMessage},
			Baseline:     websiteIssueCheck{Status: "pending", Message: pendingMessage},
			Exposure:     websiteIssueCheck{Status: "pending", Message: pendingMessage},
		},
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.state.Websites {
		if strings.EqualFold(existing.URL, monitor.URL) {
			return websiteMonitor{}, fmt.Errorf("website already exists")
		}
	}

	s.state.Websites = append(s.state.Websites, monitor)
	s.appendLogLocked("monitor", fmt.Sprintf("added website monitor %s", monitor.URL))
	if err := s.saveLocked(); err != nil {
		return websiteMonitor{}, err
	}

	s.startCheck(monitor.ID)
	return monitor, nil
}

func (s *websiteSecurityService) RemoveWebsite(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index := -1
	var target websiteMonitor
	for i, site := range s.state.Websites {
		if site.ID == id {
			index = i
			target = site
			break
		}
	}
	if index == -1 {
		return fmt.Errorf("website not found")
	}

	s.state.Websites = append(s.state.Websites[:index], s.state.Websites[index+1:]...)
	s.appendLogLocked("system", fmt.Sprintf("removed website monitor %s", target.URL))
	return s.saveLocked()
}

func (s *websiteSecurityService) RunCheckAll() {
	s.mu.RLock()
	ids := make([]string, 0, len(s.state.Websites))
	for _, site := range s.state.Websites {
		ids = append(ids, site.ID)
	}
	s.mu.RUnlock()

	for _, id := range ids {
		s.startCheck(id)
	}
}

func (s *websiteSecurityService) RunCheck(id string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, site := range s.state.Websites {
		if site.ID == id {
			s.startCheck(id)
			return nil
		}
	}
	return fmt.Errorf("website not found")
}

func (s *websiteSecurityService) ClearThreats() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.Threats = nil
	s.appendLogLocked("system", "cleared website security threats")
	return s.saveLocked()
}

func (s *websiteSecurityService) runDueChecks() {
	now := time.Now()
	s.mu.RLock()
	ids := make([]string, 0, len(s.state.Websites))
	for _, site := range s.state.Websites {
		if site.Checking {
			continue
		}
		if parseRFC3339(site.NextCheckAt).After(now) {
			continue
		}
		ids = append(ids, site.ID)
	}
	s.mu.RUnlock()

	for _, id := range ids {
		s.startCheck(id)
	}
}

func normalizeWebsiteSecurityCheckConcurrency(value int) int {
	if value <= 0 {
		return defaultWebsiteSecurityCheckConcurrency
	}
	return value
}

func (s *websiteSecurityService) startCheck(id string) {
	go s.performCheck(id)
}

func (s *websiteSecurityService) acquireCheckSlot() func() {
	if s.checkSem == nil {
		return func() {}
	}
	s.checkSem <- struct{}{}
	return func() {
		<-s.checkSem
	}
}

func (s *websiteSecurityService) performCheck(id string) {
	s.mu.Lock()
	index := -1
	for i := range s.state.Websites {
		if s.state.Websites[i].ID == id {
			index = i
			break
		}
	}
	if index == -1 || s.state.Websites[index].Checking {
		s.mu.Unlock()
		return
	}

	site := cloneWebsiteMonitor(s.state.Websites[index])
	s.state.Websites[index].Checking = true
	s.state.Websites[index].LastError = ""
	_ = s.saveLocked()
	s.mu.Unlock()

	release := s.acquireCheckSlot()
	defer release()

	updatedSite, threats, logs := s.evaluateWebsite(site)

	s.mu.Lock()
	defer s.mu.Unlock()

	index = -1
	for i := range s.state.Websites {
		if s.state.Websites[i].ID == id {
			index = i
			break
		}
	}
	if index == -1 {
		return
	}

	updatedSite.Checking = false
	updatedSite.NextCheckAt = time.Now().Add(time.Duration(updatedSite.IntervalMinutes) * time.Minute).Format(time.RFC3339)
	s.state.Websites[index] = updatedSite

	for _, threat := range threats {
		s.prependThreatLocked(threat)
	}
	for _, entry := range logs {
		s.prependLogLocked(entry)
	}

	_ = s.saveLocked()
}

func (s *websiteSecurityService) prependThreatLocked(threat websiteThreat) {
	s.state.Threats = append([]websiteThreat{threat}, s.state.Threats...)
	if len(s.state.Threats) > websiteSecurityMaxThreats {
		s.state.Threats = s.state.Threats[:websiteSecurityMaxThreats]
	}
}

func (s *websiteSecurityService) prependLogLocked(entry websiteLogEntry) {
	s.state.Logs = append([]websiteLogEntry{entry}, s.state.Logs...)
	if len(s.state.Logs) > websiteSecurityMaxLogs {
		s.state.Logs = s.state.Logs[:websiteSecurityMaxLogs]
	}
}

func (s *websiteSecurityService) appendLogLocked(kind string, message string) {
	s.prependLogLocked(newWebsiteLog(kind, message))
}

func (s *websiteSecurityService) recomputeMetricsLocked() {
	metrics := websiteSecurityMetrics{
		TotalWebsites: len(s.state.Websites),
	}

	for _, site := range s.state.Websites {
		if site.SummaryStatus == "safe" {
			metrics.HealthyWebsites++
		}

		if site.Checks.Availability.Status == "danger" {
			metrics.ActiveIssues++
			metrics.HighRiskIssues++
		}

		issueChecks := []websiteIssueCheck{
			site.Checks.Malware,
			site.Checks.Content,
			site.Checks.Baseline,
			site.Checks.Exposure,
		}
		for _, check := range issueChecks {
			metrics.ActiveIssues += check.IssueCount
			if check.Status == "danger" {
				metrics.HighRiskIssues += check.IssueCount
			}
		}

		metrics.ActiveIssues += site.Checks.Tamper.IssueCount
		if site.Checks.Tamper.Status == "danger" {
			metrics.HighRiskIssues += site.Checks.Tamper.IssueCount
		}

		if site.TargetRiskLevel == "warning" {
			metrics.TargetWarnings++
		}
	}

	s.state.Metrics = metrics
}
